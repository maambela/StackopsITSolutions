function parseJsonValue(value) {
    if (value == null || typeof value !== 'string') return value;
    const trimmed = value.trim();
    if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) return value;
    try {
        return JSON.parse(trimmed);
    } catch (_) {
        return value;
    }
}

function normalizeRow(row) {
    if (!row) return null;
    return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, parseJsonValue(value)]));
}

function toDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function findTimestamp(value) {
    if (!value || typeof value !== 'object') return null;
    const direct = value.sourceLastUpdated || value.SourceLastUpdated || value.sourceFetchedAt ||
        value.SourceFetchedAt || value.CollectedAt || value.collected_at ||
        value.LastUpdated || value.last_updated || value.UpdatedAt || value.updated_at ||
        value.CreatedAt || value.fetchedAt || value.generatedAt || value.InvoiceDate || null;
    const directDate = toDate(direct);
    if (directDate) return directDate;
    for (const payloadKey of ['Payload', 'UsersPayload', 'AssignmentsPayload']) {
        const nestedDate = toDate(value[payloadKey]?.fetchedAt || value[payloadKey]?.generatedAt);
        if (nestedDate) return nestedDate;
    }
    return null;
}

function getFreshness(records, thresholdMinutes) {
    const dates = records.map(findTimestamp).filter(Boolean);
    const lastUpdated = dates.length
        ? new Date(Math.max(...dates.map(date => date.getTime())))
        : null;
    const ageMinutes = lastUpdated
        ? Math.max(0, Math.floor((Date.now() - lastUpdated.getTime()) / 60000))
        : null;
    return {
        lastUpdated: lastUpdated ? lastUpdated.toISOString() : null,
        ageMinutes,
        stale: thresholdMinutes != null && ageMinutes != null && ageMinutes > thresholdMinutes
    };
}

async function refreshWithDeadline(refreshSource, sourceKey, companyId, timeoutMs, refreshContext = {}) {
    const deadlineMs = Math.max(0, Number(timeoutMs) || 0);
    const controller = new AbortController();
    const signals = [controller.signal, refreshContext?.signal].filter(Boolean);
    const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);
    if (!deadlineMs) return refreshSource(sourceKey, companyId, { ...refreshContext, sourceKey, signal });

    let timer = null;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
            const error = new Error(sourceKey + ' source refresh exceeded ' + deadlineMs + 'ms.');
            error.code = 'STACKCTRL_SOURCE_REFRESH_TIMEOUT';
            error.sourceKey = sourceKey;
            error.companyId = companyId;
            controller.abort(error);
            reject(error);
        }, deadlineMs);
    });

    try {
        return await Promise.race([Promise.resolve().then(() => refreshSource(sourceKey, companyId, { ...refreshContext, sourceKey, signal })), timeout]);
    } finally {
        clearTimeout(timer);
    }
}


function getLoadedFreshness(loaded, records, thresholdMinutes) {
    const recordFreshness = getFreshness(records, thresholdMinutes);

    if (recordFreshness.lastUpdated) {
        return recordFreshness;
    }

    const lineageTimestamp =
        loaded?.sourceLineage?.sourceLastUpdated ||
        loaded?.sourceLineage?.sourceFetchedAt ||
        loaded?.sourceLineage?.collectedAt ||
        loaded?.sourceLineage?.SourceLastUpdated ||
        loaded?.sourceLineage?.SourceFetchedAt ||
        loaded?.sourceLineage?.CollectedAt ||
        null;

    const lineageDate = toDate(lineageTimestamp);

    if (!lineageDate) {
        return recordFreshness;
    }

    const ageMinutes = Math.max(0, Math.floor((Date.now() - lineageDate.getTime()) / 60000));

    return {
        lastUpdated: lineageDate.toISOString(),
        ageMinutes,
        stale: thresholdMinutes != null && ageMinutes > thresholdMinutes
    };
}

function normalizeSourceLineage(sourceLineage, freshness = {}) {
    if (!sourceLineage) return null;

    return {
        ...sourceLineage,
        sourceLastUpdated: sourceLineage.sourceLastUpdated ||
            sourceLineage.sourceFetchedAt ||
            sourceLineage.collectedAt ||
            sourceLineage.updatedAt ||
            sourceLineage.createdAt ||
            freshness.lastUpdated ||
            null
    };
}

function statusResult(capability, status, overrides = {}) {
    return {
        sourceKey: capability.sourceKey,
        displayName: capability.displayName,
        status,
        isExpected: capability.isExpected,
        freshness: { lastUpdated: null, ageMinutes: null },
        metrics: {},
        evidence: [],
        warnings: [],
        rawReference: { table: null, recordId: null },
        errorMessage: null,
        ...overrides
    };
}

function notApplicableResult(capability) {
    if (!capability.isExpected) {
        return statusResult(capability, 'not_expected', {
            warnings: [`${capability.displayName} is not expected for this tenant profile.`]
        });
    }
    if (!capability.isEnabled || capability.configuration?.configured === false) {
        return statusResult(capability, 'not_configured', {
            warnings: [`${capability.displayName} is disabled or not configured for this tenant.`]
        });
    }
    return null;
}

async function queryRows(pool, sql, params) {
    const [rows] = await pool.query(sql, params);
    return rows.map(normalizeRow);
}

async function hasActiveMicrosoftTenant(pool, companyId) {
    const rows = await queryRows(
        pool,
        'SELECT ID FROM CompanyMicrosoftMapping WHERE CompanyID = ? AND IsActive = 1 LIMIT 1',
        [companyId]
    );
    return rows.length > 0;
}

function extractPayload(row, field = 'Payload') {
    return row?.[field] ?? null;
}

function primitiveMetrics(row, excluded = []) {
    if (!row || typeof row !== 'object') return {};
    const ignored = new Set(['ID', 'CompanyID', 'LastUpdated', 'CreatedAt', ...excluded]);
    return Object.fromEntries(Object.entries(row).filter(([key, value]) =>
        !ignored.has(key) && ['string', 'number', 'boolean'].includes(typeof value)
    ));
}

function summaryMetrics(payload) {
    if (!payload || typeof payload !== 'object') return {};
    return payload.summary || payload.overview || primitiveMetrics(payload, ['success', 'fetchedAt']);
}

function storedEvidenceLineage(snapshot, {
    sourceKey,
    sourceBuilder,
    sourceLayer,
    totalField,
    apiField,
    manualField
}) {
    return {
        sourceKey,
        sourceBuilder,
        sourceLayer,
        evidenceSnapshotId: snapshot?.ID || null,
        collectedAt: snapshot?.CollectedAt || null,
        sourceFetchedAt: snapshot?.SourceFetchedAt || null,
        sourceLastUpdated: snapshot?.SourceFetchedAt || snapshot?.CollectedAt || snapshot?.UpdatedAt || snapshot?.CreatedAt || null,
        sourceEndpoint: snapshot?.SourceEndpoint || null,
        collectionTrigger: snapshot?.CollectionTrigger || null,
        totalRows: Number(snapshot?.[totalField] || 0),
        apiConnectedRows: Number(snapshot?.[apiField] || 0),
        manualRowsExcluded: Number(snapshot?.[manualField] || 0),
        evidenceRecordCount: Number(snapshot?.EvidenceRecordCount || 0),
        omittedRecordCount: Number(snapshot?.OmittedRecordCount || 0),
        collectionStatus: snapshot?.CollectionStatus || 'missing',
        isComplete: Boolean(Number(snapshot?.IsComplete || 0)),
        incompleteReason: snapshot?.IncompleteReason || null,
        errorMessage: snapshot?.ErrorMessage || null
    };
}

function blockedStoredEvidenceResult({
    snapshot,
    tenantConfigured,
    table,
    displayName,
    lineageOptions
}) {
    const defaultMessage = `No complete StackCTRL ${displayName} evidence snapshot is available.`;
    const reason = snapshot?.ErrorMessage || snapshot?.IncompleteReason || defaultMessage;
    const dashboardMetrics = snapshot?.DashboardMetricsJson || {};
    return {
        status: 'missing',
        freshness: { lastUpdated: null, ageMinutes: null },
        records: [],
        notConfigured: !tenantConfigured,
        metrics: dashboardMetrics,
        dashboardSourceMetrics: dashboardMetrics,
        sourceLineage: storedEvidenceLineage(snapshot, lineageOptions),
        evidence: [],
        warnings: [`${reason} Azure analysis is blocked until API-connected evidence collection succeeds.`],
        errorMessage: reason,
        rawReference: { table, recordId: snapshot?.ID || null }
    };
}

async function collectSource(context, definition) {
    const { pool, companyId, capability, refresh, refreshSource, refreshTimeoutMs, refreshContext = {} } = context;
    const notApplicable = notApplicableResult(capability);
    if (notApplicable) return notApplicable;

    let loaded;
    let supplementalLoadWarning = null;
    let refreshWarning = null;
    let refreshErrorMessage = null;
    let refreshFailed = false;
    
    try {
        loaded = await definition.load(pool, companyId, capability);
    } catch (error) {
        if (!definition.continueWhenStoredEvidenceFails) {
            return statusResult(capability, 'error', {
                warnings: [`${capability.displayName} could not be read from StackCTRL storage.`],
                errorMessage: error.message
            });
        }
        // Live source metrics remain usable when optional historical evidence cannot be loaded.
        supplementalLoadWarning = `${capability.displayName} stored evidence could not be loaded: ${error.message}`;
        loaded = { records: [], metrics: {}, evidence: [], warnings: [] };
    }

    let records = loaded.records || [];
    let freshness = getLoadedFreshness(loaded, records, capability.freshnessThresholdMinutes);
    const shouldRefresh = capability.refreshMode !== 'stored_only' && (
        (refresh && (!records.length || freshness.stale)) ||
        (definition.refreshWhenMissing && !records.length)
    );

    if (shouldRefresh && typeof refreshSource === 'function') {
        try {
            const refreshed = await refreshWithDeadline(
                refreshSource,
                capability.sourceKey,
                companyId,
                refreshTimeoutMs,
                refreshContext
            );
            if (refreshed) {
                loaded = definition.fromRefresh
                    ? definition.fromRefresh(refreshed, loaded)
                    : { ...loaded, ...refreshed };
                records = loaded.records || [];
                freshness = getLoadedFreshness(loaded, records, capability.freshnessThresholdMinutes);
                // Clear any previous refresh error since it succeeded
                refreshFailed = false;
                refreshErrorMessage = null;
            } else {
                // Refresh returned null - reload from storage
                loaded = await definition.load(pool, companyId, capability);
                records = loaded.records || [];
                freshness = getLoadedFreshness(loaded, records, capability.freshnessThresholdMinutes);
            }
        } catch (error) {
            refreshFailed = true;
            refreshErrorMessage = error.message;
            const notConfigured = error.statusCode === 503 || /missing|not configured|credentials/i.test(error.message);
            const isRefreshError = error.isRefreshError === true;
            
            console.warn(`[Intelligence Source] ${capability.displayName} refresh error:`, {
                sourceKey: capability.sourceKey,
                companyId,
                errorMessage: error.message,
                isRefreshError,
                notConfigured,
                hasStoredData: records.length > 0
            });
            
            const normalizedSourceLineage = normalizeSourceLineage(loaded.sourceLineage, freshness);

            if (!records.length) {
                // No stored data - must fail
                return statusResult(capability, notConfigured ? 'not_configured' : 'error', {
                    warnings: [
                        ...(supplementalLoadWarning ? [supplementalLoadWarning] : []),
                        `${capability.displayName} refresh failed: ${error.message}`
                    ],
                    errorMessage: error.message,
                    sourceLineage: normalizedSourceLineage,
                    dashboardSourceMetrics: loaded.dashboardSourceMetrics || null,
                    rawReference: loaded.rawReference || { table: definition.table || null, recordId: null }
                });
            }
            
            // Has stored data - mark as stale/refresh failed
            refreshWarning = `${capability.displayName} refresh failed; the stored evidence was retained: ${error.message}`;
        }
    }

    const normalizedSourceLineage = normalizeSourceLineage(loaded.sourceLineage, freshness);
    if (!records.length) {
        const missingStatus = loaded.notConfigured ? 'not_configured' : 'missing';
        return statusResult(capability, missingStatus, {
            warnings: loaded.warnings?.length
                ? loaded.warnings
                : [`${capability.displayName} has no stored evidence for this tenant.`],
            errorMessage: loaded.sourceLineage?.errorMessage || loaded.sourceLineage?.incompleteReason || null,
            dashboardSourceMetrics: loaded.dashboardSourceMetrics || null,
            sourceLineage: normalizedSourceLineage,
            rawReference: loaded.rawReference || { table: definition.table || null, recordId: null }
        });
    }

    // If refresh failed and we're falling back to stored data, mark as stale
    const status = refreshFailed ? 'stale' : (freshness.stale ? 'stale' : 'available');
    const warnings = [...(loaded.warnings || [])];
    if (supplementalLoadWarning) warnings.push(supplementalLoadWarning);
    if (freshness.stale) warnings.push(`${capability.displayName} evidence is stale.`);
    if (refreshWarning) warnings.push(refreshWarning);

    return statusResult(capability, status, {
        freshness: {
            lastUpdated: freshness.lastUpdated,
            ageMinutes: freshness.ageMinutes 
        },
        credentialSource: ['identity', 'devices', 'email_security', 'security_alerts', 'backup', 'applications'].includes(capability.sourceKey)
            || capability.sourceKey === 'cloudflare_network_security' ? 'environment' : 'database',
        credentialPath: capability.sourceKey === 'cloudflare_network_security'
            ? 'CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN (Azure Key Vault, shared with dashboard)'
            : ['identity', 'devices', 'email_security', 'security_alerts', 'backup', 'applications'].includes(capability.sourceKey)
            ? 'MICROSOFT_CLIENT_SECRET (Azure Key Vault, shared with dashboard)'
            : 'CompanyMicrosoftMapping (per-company database)',
        refreshFailed,
        refreshErrorMessage,
        errorMessage: refreshErrorMessage || loaded.errorMessage || loaded.sourceLineage?.errorMessage || loaded.sourceLineage?.incompleteReason || null,
        metrics: loaded.metrics || definition.metrics(records),
        dashboardSourceMetrics: loaded.dashboardSourceMetrics || null,
        sourceLineage: normalizedSourceLineage,
        evidence: loaded.evidence || definition.evidence(records),
        warnings,
        rawReference: loaded.rawReference || {
            table: definition.table || null,
            recordId: records[0]?.ID || records[0]?.id || null
        }
    });
} 

const definitions = {
    identity: {
        table: 'StackCTRLIdentityEvidenceSnapshots, StackCTRLIdentityUserEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID, mt.TenantName, mt.TenantID
                                                  FROM CompanyMicrosoftMapping cm
                                                  INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
                                                  WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLIdentityEvidenceSnapshots
                     WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus = 'complete'
                     ORDER BY CollectedAt DESC, ID DESC LIMIT 1`,
                    [companyId]
                );
                const snapshot = snapshots[0];
                if (!snapshot) {
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'identity',
                            sourceBuilder: 'storedStackCTRLIdentityEvidence',
                            sourceLayer: 'StackCTRLIdentityEvidenceSnapshots',
                            collectionStatus: 'missing'
                        },
                        evidence: [],
                        warnings: ['No complete StackCTRL Identity evidence snapshot is available. Azure analysis is blocked until collection succeeds.'],
                        rawReference: { table: this.table, recordId: null }
                    };
                }
                const userRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLIdentityUserEvidence
                     WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );
                if (userRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'identity',
                            sourceBuilder: 'storedStackCTRLIdentityEvidence',
                            sourceLayer: 'StackCTRLIdentityEvidenceSnapshots',
                            evidenceSnapshotId: snapshot.ID,
                            collectionStatus: 'incomplete'
                        },
                        evidence: [],
                        warnings: [`Identity evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} user rows but ${userRows.length} were stored. Azure analysis is blocked.`],
                        rawReference: { table: this.table, recordId: snapshot.ID }
                    };
                }
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const users = userRows.map(row => row.ProcessedEvidenceJson || ({
                    id: row.UserSourceID,
                    displayName: row.Name,
                    mail: row.Email,
                    userPrincipalName: row.Email,
                    jobTitle: row.JobTitle,
                    mobilePhone: row.Phone,
                    roles: row.RolesJson || [],
                    mfaEnabled: Boolean(Number(row.MFAEnabled)),
                    authMethodCount: Number(row.AuthMethodCount || 0),
                    riskLevel: row.RiskLevel,
                    isExternal: String(row.UserType).toLowerCase() === 'external',
                    accountEnabled: String(row.AccountStatus).toLowerCase() !== 'disabled',
                    lastSignIn: {
                        dateTime: row.LastSignInAt,
                        daysSince: row.DaysSinceLastSignIn,
                        status: row.SignInStatus,
                        location: row.Location,
                        device: row.Device
                    }
                }));
                return {
                    records: snapshots,
                    notConfigured: !tenant.length,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        sourceKey: 'identity',
                        sourceBuilder: 'storedStackCTRLIdentityEvidence',
                        sourceLayer: 'StackCTRLIdentityEvidenceSnapshots + StackCTRLIdentityUserEvidence',
                        evidenceSnapshotId: snapshot.ID,
                        collectedAt: snapshot.CollectedAt,
                        sourceFetchedAt: snapshot.SourceFetchedAt,
                        sourceEndpoint: snapshot.SourceEndpoint,
                        collectionTrigger: snapshot.CollectionTrigger,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount)
                    },
                    evidence: [{ evidenceType: 'users', data: users }],
                    warnings: [],
                    rawReference: { table: this.table, recordId: snapshot.ID }
                };
            }
            const [metrics, users, roles] = await Promise.all([
                queryRows(pool, 'SELECT * FROM IdentityMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
                queryRows(pool, 'SELECT * FROM IdentityUserDetailsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
                queryRows(pool, 'SELECT * FROM MicrosoftRoleAssignmentsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId])
            ]);
            const records = [...metrics, ...users, ...roles];
            return {
                records,
                notConfigured: !tenant.length,
                metrics: metrics[0] ? primitiveMetrics(metrics[0]) : {},
                evidence: [
                    { evidenceType: 'tenant', data: tenant[0] || null },
                    { evidenceType: 'users', data: extractPayload(users[0], 'UsersPayload') || [] },
                    { evidenceType: 'role_assignments', data: extractPayload(roles[0], 'AssignmentsPayload') || [] }
                ],
                rawReference: { table: 'IdentityMetricsCache, IdentityUserDetailsCache, MicrosoftRoleAssignmentsCache', recordId: metrics[0]?.ID || null }
            };
        },
        metrics: records => primitiveMetrics(records[0]),
        evidence: records => records
    },
    devices: {
        table: 'StackCTRLDeviceEvidenceSnapshots, StackCTRLDeviceEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID, mt.TenantName, mt.TenantID
                                                  FROM CompanyMicrosoftMapping cm
                                                  INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
                                                  WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLDeviceEvidenceSnapshots
                     WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus IN ('complete', 'completed_with_warnings')
                     ORDER BY CollectedAt DESC, ID DESC LIMIT 1`,
                    [companyId]
                );
                const snapshot = snapshots[0];
                if (!snapshot) {
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'devices',
                            sourceBuilder: 'storedStackCTRLDeviceEvidence',
                            sourceLayer: 'StackCTRLDeviceEvidenceSnapshots',
                            collectionStatus: 'missing'
                        },
                        evidence: [],
                        warnings: ['No complete StackCTRL Device Protection evidence snapshot is available. Azure analysis is blocked until collection succeeds.'],
                        rawReference: { table: this.table, recordId: null }
                    };
                }
                const deviceRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLDeviceEvidence
                     WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );
                if (deviceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'devices',
                            sourceBuilder: 'storedStackCTRLDeviceEvidence',
                            sourceLayer: 'StackCTRLDeviceEvidenceSnapshots',
                            evidenceSnapshotId: snapshot.ID,
                            collectionStatus: 'incomplete'
                        },
                        evidence: [],
                        warnings: [`Device evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} device rows but ${deviceRows.length} were stored. Azure analysis is blocked.`],
                        rawReference: { table: this.table, recordId: snapshot.ID }
                    };
                }
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const sourceAudit = parseJsonValue(snapshot.SourceAuditJson, {});
                const warnings = [
                    ...(Array.isArray(sourceAudit?.warnings) ? sourceAudit.warnings : []),
                    ...(snapshot.CollectionStatus === 'completed_with_warnings' && snapshot.IncompleteReason ? [snapshot.IncompleteReason] : [])
                ];
                const devices = deviceRows.map(row => row.ProcessedEvidenceJson || ({
                    id: row.DeviceSourceID,
                    deviceName: row.DeviceName,
                    operatingSystem: row.OperatingSystem,
                    complianceState: row.ComplianceState,
                    isEncrypted: Boolean(Number(row.IsEncrypted)),
                    managementAgent: row.ManagementAgent,
                    lastSyncDateTime: row.LastSyncAt,
                    riskLevel: row.RiskLevel
                }));
                return {
                    records: snapshots,
                    notConfigured: !tenant.length,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        sourceKey: 'devices',
                        sourceBuilder: 'storedStackCTRLDeviceEvidence',
                        sourceLayer: 'StackCTRLDeviceEvidenceSnapshots + StackCTRLDeviceEvidence',
                        evidenceSnapshotId: snapshot.ID,
                        collectedAt: snapshot.CollectedAt,
                        sourceFetchedAt: snapshot.SourceFetchedAt,
                        sourceEndpoint: snapshot.SourceEndpoint,
                        collectionTrigger: snapshot.CollectionTrigger,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount)
                    },
                    evidence: [{ evidenceType: 'devices', data: devices }],
                    warnings: [...new Set(warnings)],
                    rawReference: { table: this.table, recordId: snapshot.ID }
                };
            }
            const [records, configured] = await Promise.all([
                queryRows(pool, 'SELECT * FROM DeviceMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
                hasActiveMicrosoftTenant(pool, companyId)
            ]);
            return { records, notConfigured: !configured, metrics: records[0] ? primitiveMetrics(records[0]) : {}, evidence: records };
        },
        fromRefresh(refreshed, stored) {
            const lastUpdated = refreshed.lastUpdated || refreshed.collectedAt || new Date().toISOString();
            const metrics = refreshed.dashboardMetrics || refreshed.metrics || {};
            const warnings = [...new Set([...(Array.isArray(refreshed.warnings) ? refreshed.warnings : [])])];
            const record = {
                ...metrics,
                LastUpdated: lastUpdated,
                CollectedAt: lastUpdated,
                SourceFetchedAt: lastUpdated,
                CollectionStatus: refreshed.status || refreshed.collectionStatus || (warnings.length ? 'completed_with_warnings' : 'complete')
            };
            return {
                ...stored,
                records: [record],
                metrics: Object.keys(metrics).length ? metrics : primitiveMetrics(record, ['devices']),
                dashboardSourceMetrics: Object.keys(metrics).length ? metrics : stored.dashboardSourceMetrics || null,
                evidence: refreshed.evidence || (Array.isArray(refreshed.devices) ? [{ evidenceType: 'devices', data: refreshed.devices }] : stored.evidence || []),
                warnings
            };
        },
        metrics: records => primitiveMetrics(records[0]),
        evidence: records => records
    },
    email_security: {
        table: 'StackCTRLEmailEvidenceSnapshots, StackCTRLEmailEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID, mt.TenantName, mt.TenantID
                                                  FROM CompanyMicrosoftMapping cm
                                                  INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
                                                  WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLEmailEvidenceSnapshots
                     WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus = 'complete'
                     ORDER BY CollectedAt DESC, ID DESC LIMIT 1`,
                    [companyId]
                );
                const snapshot = snapshots[0];
                if (!snapshot) {
                    const latestRows = await queryRows(
                        pool,
                        `SELECT * FROM StackCTRLEmailEvidenceSnapshots
                         WHERE CompanyID = ?
                         ORDER BY CollectedAt DESC, ID DESC LIMIT 1`,
                        [companyId]
                    );
                    const latest = latestRows[0] || null;
                    const latestMessage = latest?.ErrorMessage || latest?.IncompleteReason || 'No complete StackCTRL Email Security evidence snapshot is available.';
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: latest?.DashboardMetricsJson || {},
                        dashboardSourceMetrics: latest?.DashboardMetricsJson || {},
                        sourceLineage: {
                            ...storedEvidenceLineage(latest, {
                                sourceKey: 'email_security',
                                sourceBuilder: 'storedStackCTRLEmailEvidence',
                                sourceLayer: 'StackCTRLEmailEvidenceSnapshots'
                            }),
                            collectionStatus: latest?.CollectionStatus || 'missing'
                        },
                        evidence: [],
                        warnings: [`${latestMessage} Azure analysis is blocked until Email evidence collection succeeds.`],
                        rawReference: { table: this.table, recordId: latest?.ID || null }
                    };
                }
                const evidenceRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLEmailEvidence WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );
                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            ...storedEvidenceLineage(snapshot, {
                                sourceKey: 'email_security',
                                sourceBuilder: 'storedStackCTRLEmailEvidence',
                                sourceLayer: 'StackCTRLEmailEvidenceSnapshots'
                            }),
                            evidenceSnapshotId: snapshot.ID,
                            collectionStatus: 'incomplete',
                            incompleteReason: `Email evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored.`
                        },
                        evidence: [],
                        warnings: [`Email evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored. Azure analysis is blocked.`],
                        rawReference: { table: this.table, recordId: snapshot.ID }
                    };
                }
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const alerts = [];
                const incidents = [];
                const mailActivityUsers = [];
                evidenceRows.forEach(row => {
                    const item = row.ProcessedEvidenceJson || {};
                    if (row.EvidenceKind === 'alert') alerts.push(item);
                    else if (row.EvidenceKind === 'incident') incidents.push(item);
                    else if (row.EvidenceKind === 'mail_activity') mailActivityUsers.push(item);
                });
                return {
                    records: snapshots,
                    notConfigured: !tenant.length,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        sourceKey: 'email_security',
                        sourceBuilder: 'storedStackCTRLEmailEvidence',
                        sourceLayer: 'StackCTRLEmailEvidenceSnapshots + StackCTRLEmailEvidence',
                        evidenceSnapshotId: snapshot.ID,
                        collectedAt: snapshot.CollectedAt,
                        sourceFetchedAt: snapshot.SourceFetchedAt,
                        sourceLastUpdated: snapshot.SourceFetchedAt || snapshot.CollectedAt || snapshot.UpdatedAt || snapshot.CreatedAt,
                        sourceEndpoint: snapshot.SourceEndpoint,
                        collectionTrigger: snapshot.CollectionTrigger,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount)
                    },
                    evidence: [
                        { evidenceType: 'alerts', data: alerts },
                        { evidenceType: 'incidents', data: incidents },
                        { evidenceType: 'mailActivityUsers', data: mailActivityUsers }
                    ],
                    warnings: [],
                    rawReference: { table: this.table, recordId: snapshot.ID }
                };
            }
            const [metrics, payloadRows, configured] = await Promise.all([
                queryRows(pool, 'SELECT * FROM EmailMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
                queryRows(pool, 'SELECT * FROM EmailSecurityPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]),
                hasActiveMicrosoftTenant(pool, companyId)
            ]);
            const payload = extractPayload(payloadRows[0]);
            return {
                records: [...metrics, ...payloadRows],
                notConfigured: !configured,
                metrics: metrics[0] ? primitiveMetrics(metrics[0]) : summaryMetrics(payload),
                evidence: payload ? [payload] : []
            };
        },
        fromRefresh(refreshed, stored) {
            return stored;
        },
        metrics: records => primitiveMetrics(records[0]),
        evidence: records => records
    },
    security_alerts: {
        table: 'StackCTRLSecurityEvidenceSnapshots, StackCTRLSecurityEvidence',
        refreshWhenMissing: true,

async load(pool, companyId, capability) {
    const tenant = await queryRows(
        pool,
        `SELECT mt.ID AS MicrosoftTenantID
         FROM CompanyMicrosoftMapping cm
         INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
         WHERE cm.CompanyID = ? AND cm.IsActive = 1
         LIMIT 1`,
        [companyId]
    );

    if (capability?.profileKey === 'sunbird') {
        const lineageOptions = {
            sourceKey: 'security_alerts',
            sourceBuilder: 'storedStackCTRLSecurityEvidence',
            sourceLayer: 'StackCTRLSecurityEvidenceSnapshots'
        };

        const toIso = value => {
            if (!value) return null;
            const date = value instanceof Date ? value : new Date(value);
            return Number.isNaN(date.getTime()) ? null : date.toISOString();
        };

        const sourceTimestamp = snapshot => toIso(
            snapshot?.SourceFetchedAt ||
            snapshot?.sourceFetchedAt ||
            snapshot?.SourceLastUpdated ||
            snapshot?.sourceLastUpdated ||
            snapshot?.CollectedAt ||
            snapshot?.UpdatedAt ||
            snapshot?.CreatedAt
        );

        const latestRows = await queryRows(
            pool,
            `SELECT *
             FROM StackCTRLSecurityEvidenceSnapshots
             WHERE CompanyID = ?
             ORDER BY CollectedAt DESC, ID DESC
             LIMIT 1`,
            [companyId]
        );

        const latest = latestRows[0] || null;

        const completeRows = await queryRows(
            pool,
            `SELECT *
             FROM StackCTRLSecurityEvidenceSnapshots
             WHERE CompanyID = ?
               AND IsComplete = 1
               AND CollectionStatus IN ('complete', 'completed_with_warnings')
             ORDER BY CollectedAt DESC, ID DESC
             LIMIT 1`,
            [companyId]
        );

        const snapshot = completeRows[0] || null;

        const latestError =
            latest?.ErrorMessage ||
            latest?.IncompleteReason ||
            null;

        const latestIsFailed = latest && (
            Number(latest.IsComplete || 0) !== 1 ||
            ['failed_terminal', 'failed', 'error'].includes(String(latest.CollectionStatus || '').toLowerCase())
        );

        const latestIsNewerThanComplete = latestIsFailed && snapshot
            ? new Date(latest.CollectedAt || latest.CreatedAt || 0).getTime() >=
              new Date(snapshot.CollectedAt || snapshot.CreatedAt || 0).getTime()
            : Boolean(latestIsFailed && !snapshot);

        if (!snapshot) {
            const storedError =
                latestError ||
                'No complete StackCTRL Security Alerts evidence snapshot is available. Azure analysis is blocked until collection succeeds.';

            const latestTimestamp = sourceTimestamp(latest);

            return {
                records: [],
                notConfigured: !tenant.length,
                metrics: latest?.DashboardMetricsJson || {},
                dashboardSourceMetrics: latest?.DashboardMetricsJson || {},
                sourceLineage: {
                    ...storedEvidenceLineage(latest, lineageOptions),
                    collectionStatus: latest?.CollectionStatus || 'missing',
                    isComplete: latest ? Boolean(Number(latest.IsComplete)) : false,
                    evidenceSnapshotId: latest?.ID || null,
                    collectedAt: latest?.CollectedAt || null,
                    sourceFetchedAt: latestTimestamp,
                    sourceLastUpdated: latestTimestamp,
                    incompleteReason: latest?.IncompleteReason || storedError,
                    errorMessage: storedError
                },
                evidence: [],
                warnings: [storedError],
                rawReference: {
                    table: this.table,
                    recordId: latest?.ID || null
                },
                errorMessage: storedError
            };
        }

        const evidenceRows = await queryRows(
            pool,
            `SELECT *
             FROM StackCTRLSecurityEvidence
             WHERE SnapshotID = ?
             ORDER BY ID`,
            [snapshot.ID]
        );

        if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
            const errorMessage = `Security evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored.`;
            const timestamp = sourceTimestamp(snapshot);

            return {
                records: [],
                notConfigured: !tenant.length,
                metrics: snapshot.DashboardMetricsJson || {},
                dashboardSourceMetrics: snapshot.DashboardMetricsJson || {},
                sourceLineage: {
                    ...storedEvidenceLineage(snapshot, lineageOptions),
                    collectionStatus: 'incomplete',
                    isComplete: false,
                    evidenceSnapshotId: snapshot.ID,
                    collectedAt: snapshot.CollectedAt || null,
                    sourceFetchedAt: timestamp,
                    sourceLastUpdated: timestamp,
                    incompleteReason: errorMessage,
                    errorMessage
                },
                evidence: [],
                warnings: [`${errorMessage} Azure analysis is blocked.`],
                rawReference: {
                    table: this.table,
                    recordId: snapshot.ID
                },
                errorMessage
            };
        }

        const grouped = {
            alerts: [],
            incidents: [],
            signIns: [],
            threatIndicators: []
        };

        evidenceRows.forEach(row => {
            const item = row.ProcessedEvidenceJson || {};

            if (row.EvidenceKind === 'alert') grouped.alerts.push(item);
            else if (row.EvidenceKind === 'incident') grouped.incidents.push(item);
            else if (row.EvidenceKind === 'sign_in') grouped.signIns.push(item);
            else if (row.EvidenceKind === 'threat_indicator') grouped.threatIndicators.push(item);
        });

        const dashboardMetrics = snapshot.DashboardMetricsJson || {};
        const sourceAudit = parseJsonValue(snapshot.SourceAuditJson, {});
        const auditWarnings = Array.isArray(sourceAudit?.warnings) ? sourceAudit.warnings : [];

        const hasPrimaryEvidence = Boolean(
            grouped.alerts.length ||
            grouped.incidents.length ||
            grouped.signIns.length
        );

        const hasThreatIndicators = grouped.threatIndicators.length > 0;

        const rawWarnings = [
            ...(latestIsNewerThanComplete && latestError ? [latestError] : []),
            ...auditWarnings,
            ...(snapshot.CollectionStatus === 'completed_with_warnings' && snapshot.IncompleteReason
                ? String(snapshot.IncompleteReason).split(';').map(item => item.trim()).filter(Boolean)
                : [])
        ];

        const warnings = [...new Set(rawWarnings)].filter(warning => {
            const lower = String(warning || '').toLowerCase();

            if (!warning) return false;

            if (lower.includes('threat indicators') || lower.includes('threat_indicators_unavailable')) {
                return !hasThreatIndicators;
            }

            if (lower.includes('alerts fetch failed') || lower.includes('alerts_unavailable')) {
                return grouped.alerts.length === 0;
            }

            if (lower.includes('incidents fetch failed') || lower.includes('incidents_unavailable')) {
                return grouped.incidents.length === 0;
            }

            if (lower.includes('sign-ins fetch failed') || lower.includes('signins_unavailable')) {
                return grouped.signIns.length === 0;
            }

            if (lower.includes('partial_source_collection')) {
                return !hasPrimaryEvidence;
            }

            return true;
        });

        const timestamp = sourceTimestamp(snapshot);

        const records = [{
            ...snapshot,
            SourceFetchedAt: timestamp,
            sourceFetchedAt: timestamp,
            SourceLastUpdated: timestamp,
            sourceLastUpdated: timestamp,
            LastUpdated: timestamp,
            last_updated: timestamp,
            UpdatedAt: timestamp
        }];

        return {
            records,
            notConfigured: !tenant.length,
            metrics: dashboardMetrics,
            dashboardSourceMetrics: dashboardMetrics,
            sourceLineage: {
                sourceKey: 'security_alerts',
                sourceBuilder: 'storedStackCTRLSecurityEvidence',
                sourceLayer: 'StackCTRLSecurityEvidenceSnapshots + StackCTRLSecurityEvidence',
                evidenceSnapshotId: snapshot.ID,
                collectedAt: snapshot.CollectedAt || null,
                sourceFetchedAt: timestamp,
                sourceLastUpdated: timestamp,
                sourceEndpoint: snapshot.SourceEndpoint,
                collectionTrigger: snapshot.CollectionTrigger,
                collectionStatus: snapshot.CollectionStatus,
                isComplete: Boolean(Number(snapshot.IsComplete)),
                evidenceRecordCount: Number(snapshot.EvidenceRecordCount),
                expectedRecordCount: Number(snapshot.ExpectedRecordCount),
                omittedRecordCount: Number(snapshot.OmittedRecordCount),
                incompleteReason: warnings.length ? warnings.join('; ') : null,
                errorMessage: latestIsNewerThanComplete && latestError ? latestError : (snapshot.ErrorMessage || null),
                latestCollectionFailure: latestIsNewerThanComplete && latestError ? {
                    snapshotId: latest.ID,
                    collectionStatus: latest.CollectionStatus,
                    errorMessage: latestError,
                    collectedAt: latest.CollectedAt || latest.CreatedAt || null
                } : null,
                stages: sourceAudit?.collection?.stages || sourceAudit?.stages || [],
                internalThreatIndicatorsAvailable: hasThreatIndicators,
                hasPrimaryEvidence
            },
            evidence: Object.entries(grouped).map(([evidenceType, data]) => ({
                evidenceType,
                data
            })),
            warnings,
            rawReference: {
                table: this.table,
                recordId: snapshot.ID
            },
            errorMessage: latestIsNewerThanComplete && latestError ? latestError : null
        };
    }

    const [records, configured] = await Promise.all([
        queryRows(
            pool,
            'SELECT * FROM SecurityEventsPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
            [companyId]
        ),
        hasActiveMicrosoftTenant(pool, companyId)
    ]);

    const payload = extractPayload(records[0]);

    return {
        records,
        notConfigured: !configured,
        metrics: summaryMetrics(payload),
        evidence: payload ? [payload] : []
    };
},

        fromRefresh(refreshed, stored) {
            return stored;
        },

        metrics: records => summaryMetrics(extractPayload(records[0])),

        evidence: records => records
    },
    backup: {
        table: 'StackCTRLBackupEvidenceSnapshots, StackCTRLBackupEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID FROM CompanyMicrosoftMapping cm INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(pool, `SELECT * FROM StackCTRLBackupEvidenceSnapshots WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus = 'complete' ORDER BY CollectedAt DESC, ID DESC LIMIT 1`, [companyId]);
                const snapshot = snapshots[0];
                if (!snapshot) return { records: [], notConfigured: !tenant.length, metrics: {}, dashboardSourceMetrics: {}, sourceLineage: { sourceKey: 'backup', sourceBuilder: 'storedStackCTRLBackupEvidence', sourceLayer: 'StackCTRLBackupEvidenceSnapshots', collectionStatus: 'missing' }, evidence: [], warnings: ['No complete StackCTRL Backup and Recovery evidence snapshot is available. Azure analysis is blocked until collection succeeds.'], rawReference: { table: this.table, recordId: null } };
                const evidenceRows = await queryRows(pool, `SELECT * FROM StackCTRLBackupEvidence WHERE SnapshotID = ? ORDER BY ID`, [snapshot.ID]);
                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) return { records: [], notConfigured: !tenant.length, metrics: {}, dashboardSourceMetrics: {}, sourceLineage: { sourceKey: 'backup', sourceBuilder: 'storedStackCTRLBackupEvidence', evidenceSnapshotId: snapshot.ID, collectionStatus: 'incomplete' }, evidence: [], warnings: [`Backup evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored. Azure analysis is blocked.`], rawReference: { table: this.table, recordId: snapshot.ID } };
                const users = [];
                const sites = [];
                evidenceRows.forEach(row => {
                    const item = row.ProcessedEvidenceJson || {};
                    if (row.EvidenceKind === 'site') sites.push(item);
                    else users.push(item);
                });
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                return { records: snapshots, notConfigured: !tenant.length, metrics: dashboardMetrics, dashboardSourceMetrics: dashboardMetrics, sourceLineage: { sourceKey: 'backup', sourceBuilder: 'storedStackCTRLBackupEvidence', sourceLayer: 'StackCTRLBackupEvidenceSnapshots + StackCTRLBackupEvidence', evidenceSnapshotId: snapshot.ID, collectedAt: snapshot.CollectedAt, sourceFetchedAt: snapshot.SourceFetchedAt, sourceEndpoint: snapshot.SourceEndpoint, collectionTrigger: snapshot.CollectionTrigger, collectionStatus: snapshot.CollectionStatus, isComplete: Boolean(Number(snapshot.IsComplete)), evidenceRecordCount: Number(snapshot.EvidenceRecordCount), omittedRecordCount: Number(snapshot.OmittedRecordCount) }, evidence: [{ evidenceType: 'users', data: users }, { evidenceType: 'sites', data: sites }], warnings: [], rawReference: { table: this.table, recordId: snapshot.ID } };
            }
            const [records, configured] = await Promise.all([queryRows(pool, 'SELECT * FROM BackupRecoveryPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]), hasActiveMicrosoftTenant(pool, companyId)]);
            const payload = extractPayload(records[0]);
            return { records, notConfigured: !configured, metrics: summaryMetrics(payload), evidence: payload ? [payload] : [] };
        },
        fromRefresh(refreshed, stored) { return stored; },
        metrics: records => summaryMetrics(extractPayload(records[0])),
        evidence: records => records
    },
    applications: {
        table: 'StackCTRLApplicationsEvidenceSnapshots, StackCTRLApplicationsEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID FROM CompanyMicrosoftMapping cm INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(pool, `SELECT * FROM StackCTRLApplicationsEvidenceSnapshots WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus = 'complete' ORDER BY CollectedAt DESC, ID DESC LIMIT 1`, [companyId]);
                const snapshot = snapshots[0];
                if (!snapshot) return { records: [], notConfigured: !tenant.length, metrics: {}, dashboardSourceMetrics: {}, sourceLineage: { sourceKey: 'applications', sourceBuilder: 'storedStackCTRLApplicationsEvidence', sourceLayer: 'StackCTRLApplicationsEvidenceSnapshots', collectionStatus: 'missing' }, evidence: [], warnings: ['No complete StackCTRL Applications evidence snapshot is available. Azure analysis is blocked until collection succeeds.'], rawReference: { table: this.table, recordId: null } };
                const evidenceRows = await queryRows(pool, `SELECT * FROM StackCTRLApplicationsEvidence WHERE SnapshotID = ? ORDER BY ID`, [snapshot.ID]);
                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) return { records: [], notConfigured: !tenant.length, metrics: {}, dashboardSourceMetrics: {}, sourceLineage: { sourceKey: 'applications', sourceBuilder: 'storedStackCTRLApplicationsEvidence', evidenceSnapshotId: snapshot.ID, collectionStatus: 'incomplete' }, evidence: [], warnings: [`Applications evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored. Azure analysis is blocked.`], rawReference: { table: this.table, recordId: snapshot.ID } };
                const applications = evidenceRows.map(row => row.ProcessedEvidenceJson || {});
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                return { records: snapshots, notConfigured: !tenant.length, metrics: dashboardMetrics, dashboardSourceMetrics: dashboardMetrics, sourceLineage: { sourceKey: 'applications', sourceBuilder: 'storedStackCTRLApplicationsEvidence', sourceLayer: 'StackCTRLApplicationsEvidenceSnapshots + StackCTRLApplicationsEvidence', evidenceSnapshotId: snapshot.ID, collectedAt: snapshot.CollectedAt, sourceFetchedAt: snapshot.SourceFetchedAt, sourceEndpoint: snapshot.SourceEndpoint, collectionTrigger: snapshot.CollectionTrigger, collectionStatus: snapshot.CollectionStatus, isComplete: Boolean(Number(snapshot.IsComplete)), evidenceRecordCount: Number(snapshot.EvidenceRecordCount), omittedRecordCount: Number(snapshot.OmittedRecordCount) }, evidence: [{ evidenceType: 'applications', data: applications }], warnings: [], rawReference: { table: this.table, recordId: snapshot.ID } };
            }
            const [metrics, payloadRows, configured] = await Promise.all([queryRows(pool, 'SELECT * FROM ApplicationMetricsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]), queryRows(pool, 'SELECT * FROM ApplicationPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]), hasActiveMicrosoftTenant(pool, companyId)]);
            const payload = extractPayload(payloadRows[0]);
            return { records: [...metrics, ...payloadRows], notConfigured: !configured, metrics: metrics[0] ? primitiveMetrics(metrics[0]) : summaryMetrics(payload), evidence: payload ? [payload] : [] };
        },
        fromRefresh(refreshed, stored) { return stored; },
        metrics: records => primitiveMetrics(records[0]),
        evidence: records => records
    },
    governance: {
        table: 'StackCTRLGovernanceEvidenceSnapshots, StackCTRLGovernanceEvidence',
        refreshWhenMissing: true,

        async load(pool, companyId, capability) {
            const tenant = await queryRows(
                pool,
                `SELECT mt.ID AS MicrosoftTenantID
                FROM CompanyMicrosoftMapping cm
                INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
                WHERE cm.CompanyID = ? AND cm.IsActive = 1
                LIMIT 1`,
                [companyId]
            );

            const lineageOptions = {
                sourceKey: 'governance',
                sourceBuilder: 'storedStackCTRLGovernanceEvidence',
                sourceLayer: 'StackCTRLGovernanceEvidenceSnapshots',
                totalField: 'TotalRows',
                apiField: 'ApiConnectedRows',
                manualField: 'ManualRowsExcluded'
            };

            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT *
                    FROM StackCTRLGovernanceEvidenceSnapshots
                    WHERE CompanyID = ?
                    AND IsComplete = 1
                    AND CollectionStatus IN ('complete', 'completed_with_warnings')
                    ORDER BY CollectedAt DESC, ID DESC
                    LIMIT 1`,
                    [companyId]
                );

                const snapshot = snapshots[0];

                if (!snapshot || !Number(snapshot.IsComplete) || !['complete', 'completed_with_warnings'].includes(String(snapshot.CollectionStatus || ''))) {
                    const latestRows = await queryRows(
                        pool,
                        `SELECT *
                        FROM StackCTRLGovernanceEvidenceSnapshots
                        WHERE CompanyID = ?
                        ORDER BY CollectedAt DESC, ID DESC
                        LIMIT 1`,
                        [companyId]
                    );

                    return blockedStoredEvidenceResult({
                        snapshot: latestRows[0] || snapshot,
                        tenantConfigured: tenant.length > 0,
                        table: this.table,
                        displayName: 'Governance',
                        lineageOptions
                    });
                }

                const evidenceRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLGovernanceEvidence WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );

                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    const errorMessage = `Governance evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored.`;

                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: snapshot.DashboardMetricsJson || {},
                        dashboardSourceMetrics: snapshot.DashboardMetricsJson || {},
                        sourceLineage: {
                            ...storedEvidenceLineage(snapshot, lineageOptions),
                            collectionStatus: 'incomplete',
                            isComplete: false,
                            incompleteReason: errorMessage,
                            errorMessage
                        },
                        evidence: [],
                        warnings: [`${errorMessage} Azure analysis is blocked.`],
                        rawReference: {
                            table: this.table,
                            recordId: snapshot.ID
                        },
                        errorMessage
                    };
                }

                const governanceRows = evidenceRows.map(row => ({
                    ...(row.ProcessedEvidenceJson || {}),
                    evidenceKind: row.EvidenceKind,
                    sourceId: row.SourceID,
                    title: row.Title,
                    area: row.Area,
                    status: row.Status,
                    evidenceRowId: row.ID
                }));

                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const sourceAudit = snapshot.SourceAuditJson || {};

                const warnings = [
                    ...(Array.isArray(sourceAudit?.warnings) ? sourceAudit.warnings : []),
                    ...(snapshot.CollectionStatus === 'completed_with_warnings' && snapshot.IncompleteReason
                        ? String(snapshot.IncompleteReason).split(';').map(item => item.trim()).filter(Boolean)
                        : [])
                ].filter(Boolean);

                const sourceTimestamp = snapshot.SourceFetchedAt || snapshot.CollectedAt || snapshot.CreatedAt || null;

                return {
                    records: [{
                        ...snapshot,
                        SourceLastUpdated: sourceTimestamp,
                        sourceLastUpdated: sourceTimestamp,
                        sourceFetchedAt: snapshot.SourceFetchedAt || null
                    }],
                    notConfigured: !tenant.length,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        ...storedEvidenceLineage(snapshot, {
                            ...lineageOptions,
                            sourceLayer: 'StackCTRLGovernanceEvidenceSnapshots + StackCTRLGovernanceEvidence'
                        }),
                        sourceLastUpdated: sourceTimestamp,
                        sourceFetchedAt: snapshot.SourceFetchedAt || null,
                        evidenceSnapshotId: snapshot.ID,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount || 0),
                        expectedRecordCount: Number(snapshot.ExpectedRecordCount || 0),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount || 0),
                        manualRowsExcluded: Number(snapshot.ManualRowsExcluded || 0),
                        totalRows: Number(snapshot.TotalRows || 0),
                        apiConnectedRows: Number(snapshot.ApiConnectedRows || 0),
                        incompleteReason: warnings.length ? warnings.join('; ') : null,
                        errorMessage: snapshot.ErrorMessage || null
                    },
                    evidence: [{
                        evidenceType: 'governanceRows',
                        data: governanceRows
                    }],
                    warnings,
                    rawReference: {
                        table: this.table,
                        recordId: snapshot.ID
                    }
                };
            }

            const [records, configured] = await Promise.all([
                queryRows(
                    pool,
                    'SELECT * FROM SunbirdGovernancePayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
                    [companyId]
                ),
                hasActiveMicrosoftTenant(pool, companyId)
            ]);

            const payload = extractPayload(records[0]);

            return {
                records,
                notConfigured: !configured,
                metrics: summaryMetrics(payload),
                evidence: payload ? [payload] : []
            };
        },

        fromRefresh(refreshed, stored) {
            return stored;
        },

        metrics: records => summaryMetrics(extractPayload(records[0])),
        evidence: records => records
    },
    compliance: {
        table: 'StackCTRLComplianceEvidenceSnapshots, StackCTRLComplianceEvidence',
        refreshWhenMissing: true,

        async load(pool, companyId, capability) {
            const tenant = await queryRows(
                pool,
                `SELECT mt.ID AS MicrosoftTenantID
                 FROM CompanyMicrosoftMapping cm
                 INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID
                 WHERE cm.CompanyID = ? AND cm.IsActive = 1
                 LIMIT 1`,
                [companyId]
            );

            const lineageOptions = {
                sourceKey: 'compliance',
                sourceBuilder: 'storedStackCTRLComplianceEvidence',
                sourceLayer: 'StackCTRLComplianceEvidenceSnapshots',
                totalField: 'TotalControls',
                apiField: 'ApiControls',
                manualField: 'ManualControlsExcluded'
            };

            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT *
                     FROM StackCTRLComplianceEvidenceSnapshots
                     WHERE CompanyID = ?
                       AND IsComplete = 1
                       AND CollectionStatus IN ('complete', 'completed_with_warnings')
                     ORDER BY CollectedAt DESC, ID DESC
                     LIMIT 1`,
                    [companyId]
                );

                const snapshot = snapshots[0];

                if (!snapshot || !Number(snapshot.IsComplete) || !['complete', 'completed_with_warnings'].includes(String(snapshot.CollectionStatus || ''))) {
                    const latestRows = await queryRows(
                        pool,
                        `SELECT *
                         FROM StackCTRLComplianceEvidenceSnapshots
                         WHERE CompanyID = ?
                         ORDER BY CollectedAt DESC, ID DESC
                         LIMIT 1`,
                        [companyId]
                    );

                    return blockedStoredEvidenceResult({
                        snapshot: latestRows[0] || snapshot,
                        tenantConfigured: tenant.length > 0,
                        table: this.table,
                        displayName: 'Compliance Validation',
                        lineageOptions
                    });
                }

                const evidenceRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLComplianceEvidence WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );

                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    const errorMessage = `Compliance evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored.`;

                    return {
                        records: [],
                        notConfigured: !tenant.length,
                        metrics: snapshot.DashboardMetricsJson || {},
                        dashboardSourceMetrics: snapshot.DashboardMetricsJson || {},
                        sourceLineage: {
                            ...storedEvidenceLineage(snapshot, lineageOptions),
                            collectionStatus: 'incomplete',
                            isComplete: false,
                            incompleteReason: errorMessage,
                            errorMessage
                        },
                        evidence: [],
                        warnings: [`${errorMessage} Azure analysis is blocked.`],
                        rawReference: {
                            table: this.table,
                            recordId: snapshot.ID
                        },
                        errorMessage
                    };
                }

                const controls = evidenceRows.map(row => ({
                    ...(row.ProcessedEvidenceJson || {}),
                    evidenceKind: row.EvidenceKind,
                    sourceId: row.SourceID,
                    title: row.Title,
                    area: row.Area,
                    status: row.Status,
                    evidenceRowId: row.ID
                }));

                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const sourceAudit = snapshot.SourceAuditJson || {};

                const warnings = [
                    ...(Array.isArray(sourceAudit?.warnings) ? sourceAudit.warnings : []),
                    ...(snapshot.CollectionStatus === 'completed_with_warnings' && snapshot.IncompleteReason
                        ? String(snapshot.IncompleteReason).split(';').map(item => item.trim()).filter(Boolean)
                        : [])
                ].filter(Boolean);

                const sourceTimestamp = snapshot.SourceFetchedAt || snapshot.CollectedAt || snapshot.CreatedAt || null;

                return {
                    records: [{
                        ...snapshot,
                        SourceLastUpdated: sourceTimestamp,
                        sourceLastUpdated: sourceTimestamp,
                        sourceFetchedAt: snapshot.SourceFetchedAt || null
                    }],
                    notConfigured: !tenant.length,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        ...storedEvidenceLineage(snapshot, {
                            ...lineageOptions,
                            sourceLayer: 'StackCTRLComplianceEvidenceSnapshots + StackCTRLComplianceEvidence'
                        }),
                        sourceLastUpdated: sourceTimestamp,
                        sourceFetchedAt: snapshot.SourceFetchedAt || null,
                        evidenceSnapshotId: snapshot.ID,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount || 0),
                        expectedRecordCount: Number(snapshot.ExpectedRecordCount || 0),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount || 0),
                        manualRowsExcluded: Number(snapshot.ManualControlsExcluded || 0),
                        totalControls: Number(snapshot.TotalControls || 0),
                        apiControls: Number(snapshot.ApiControls || 0),
                        incompleteReason: warnings.length ? warnings.join('; ') : null,
                        errorMessage: snapshot.ErrorMessage || null
                    },
                    evidence: [{
                        evidenceType: 'controls',
                        data: controls
                    }],
                    warnings,
                    rawReference: {
                        table: this.table,
                        recordId: snapshot.ID
                    }
                };
            }

            const [records, configured] = await Promise.all([
                queryRows(
                    pool,
                    'SELECT * FROM SunbirdComplianceControlsCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1',
                    [companyId]
                ),
                hasActiveMicrosoftTenant(pool, companyId)
            ]);

            const payload = extractPayload(records[0]);

            return {
                records,
                notConfigured: !configured,
                metrics: summaryMetrics(payload),
                evidence: payload ? [payload] : []
            };
        },

        fromRefresh(refreshed, stored) {
            return stored;
        },

        metrics: records => summaryMetrics(extractPayload(records[0])),
        evidence: records => records
    },
    operations: {
        table: 'StackCTRLOperationsEvidenceSnapshots, StackCTRLOperationsEvidence',
        refreshWhenMissing: true,
        async load(pool, companyId, capability) {
            const tenant = await queryRows(pool, `SELECT mt.ID AS MicrosoftTenantID FROM CompanyMicrosoftMapping cm INNER JOIN MicrosoftTenants mt ON mt.ID = cm.MicrosoftTenantID WHERE cm.CompanyID = ? AND cm.IsActive = 1 LIMIT 1`, [companyId]);
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(pool, `SELECT * FROM StackCTRLOperationsEvidenceSnapshots WHERE CompanyID = ? ORDER BY CollectedAt DESC, ID DESC LIMIT 1`, [companyId]);
                const snapshot = snapshots[0];
                const lineageOptions = { sourceKey: 'operations', sourceBuilder: 'storedStackCTRLOperationsEvidence', sourceLayer: 'StackCTRLOperationsEvidenceSnapshots', totalField: 'TotalTasks', apiField: 'ApiTasks', manualField: 'ManualTasksExcluded' };
                if (!snapshot || !Number(snapshot.IsComplete) || snapshot.CollectionStatus !== 'complete') {
                    return blockedStoredEvidenceResult({ snapshot, tenantConfigured: tenant.length > 0, table: this.table, displayName: 'Operations', lineageOptions });
                }
                const evidenceRows = await queryRows(pool, `SELECT * FROM StackCTRLOperationsEvidence WHERE SnapshotID = ? ORDER BY ID`, [snapshot.ID]);
                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    const errorMessage = `Operations evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored.`;
                    return { records: [], notConfigured: !tenant.length, metrics: snapshot.DashboardMetricsJson || {}, dashboardSourceMetrics: snapshot.DashboardMetricsJson || {}, sourceLineage: { ...storedEvidenceLineage(snapshot, lineageOptions), collectionStatus: 'incomplete', isComplete: false, incompleteReason: errorMessage, errorMessage }, evidence: [], warnings: [`${errorMessage} Azure analysis is blocked.`], rawReference: { table: this.table, recordId: snapshot.ID } };
                }
                const tasks = evidenceRows.map(row => row.ProcessedEvidenceJson || {});
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                return { records: snapshots, notConfigured: !tenant.length, metrics: dashboardMetrics, dashboardSourceMetrics: dashboardMetrics, sourceLineage: storedEvidenceLineage(snapshot, { ...lineageOptions, sourceLayer: 'StackCTRLOperationsEvidenceSnapshots + StackCTRLOperationsEvidence' }), evidence: [{ evidenceType: 'tasks', data: tasks }], warnings: [], rawReference: { table: this.table, recordId: snapshot.ID } };
            }
            const [records, configured] = await Promise.all([queryRows(pool, 'SELECT * FROM SunbirdOperationsPayloadCache WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1', [companyId]), hasActiveMicrosoftTenant(pool, companyId)]);
            const payload = extractPayload(records[0]);
            return { records, notConfigured: !configured, metrics: summaryMetrics(payload), evidence: payload ? [payload] : [] };
        },
        fromRefresh(refreshed, stored) { return stored; },
        metrics: records => summaryMetrics(extractPayload(records[0])),
        evidence: records => records
    },
    cloudflare_network_security: {
        table: 'StackCTRLNetworkEvidenceSnapshots, StackCTRLNetworkEvidence',
        refreshWhenMissing: true,
        continueWhenStoredEvidenceFails: true,
        async load(pool, companyId, capability) {
            if (capability?.profileKey === 'sunbird') {
                const snapshots = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLNetworkEvidenceSnapshots
                     WHERE CompanyID = ? AND IsComplete = 1 AND CollectionStatus IN ('complete', 'completed_with_warnings')
                     ORDER BY CollectedAt DESC, ID DESC LIMIT 1`,
                    [companyId]
                );
                const snapshot = snapshots[0];
                if (!snapshot) {
                    return {
                        records: [],
                        notConfigured: false,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'cloudflare_network_security',
                            sourceBuilder: 'storedStackCTRLNetworkEvidence',
                            sourceLayer: 'StackCTRLNetworkEvidenceSnapshots',
                            collectionStatus: 'missing'
                        },
                        evidence: [],
                        warnings: ['No complete StackCTRL Network Security evidence snapshot is available. Azure analysis is blocked until collection succeeds.'],
                        rawReference: { table: this.table, recordId: null }
                    };
                }
                const evidenceRows = await queryRows(
                    pool,
                    `SELECT * FROM StackCTRLNetworkEvidence WHERE SnapshotID = ? ORDER BY ID`,
                    [snapshot.ID]
                );
                if (evidenceRows.length !== Number(snapshot.EvidenceRecordCount)) {
                    return {
                        records: [],
                        notConfigured: false,
                        metrics: {},
                        dashboardSourceMetrics: {},
                        sourceLineage: {
                            sourceKey: 'cloudflare_network_security',
                            sourceBuilder: 'storedStackCTRLNetworkEvidence',
                            sourceLayer: 'StackCTRLNetworkEvidenceSnapshots',
                            evidenceSnapshotId: snapshot.ID,
                            collectionStatus: 'incomplete'
                        },
                        evidence: [],
                        warnings: [`Network evidence snapshot ${snapshot.ID} expected ${snapshot.EvidenceRecordCount} rows but ${evidenceRows.length} were stored. Azure analysis is blocked.`],
                        rawReference: { table: this.table, recordId: snapshot.ID }
                    };
                }
                const dashboardMetrics = snapshot.DashboardMetricsJson || {};
                const grouped = {
                    accessApps: [],
                    devices: [],
                    deviceRegistrations: [],
                    devicePosture: [],
                    gatewayRules: [],
                    accessPolicies: [],
                    accessLogs: [],
                    dlpProfiles: [],
                    warpProfiles: [],
                    virtualNetworks: [],
                    gatewayAppTypes: [],
                    permissionMatrix: [],
                    auditLogs: [],
                    accountLogs: [],
                    securityInsights: [],
                    applicationSecurityReports: [],
                    apiGatewayOperations: [],
                    casbFindings: [],
                    tunnels: [],
                    cloudforceRequests: [],
                    intelFeeds: [],
                    dnsFirewallRules: [],
                    loadBalancerPools: [],
                    loadBalancerMonitors: [],
                    magicWanSites: [],
                    magicWanRoutes: [],
                    mtlsCertificates: [],
                    accessGroups: [],
                    accessOrganizations: [],
                    accessCertificates: [],
                    warpConnectors: [],
                    teamnetRoutes: [],
                    teamsDexTests: []
                };
                evidenceRows.forEach(row => {
                    const item = row.ProcessedEvidenceJson || {};
                    if (row.EvidenceKind === 'access_app') grouped.accessApps.push(item);
                    else if (row.EvidenceKind === 'device') grouped.devices.push(item);
                    else if (row.EvidenceKind === 'device_registration') grouped.deviceRegistrations.push(item);
                    else if (row.EvidenceKind === 'device_posture') grouped.devicePosture.push(item);
                    else if (row.EvidenceKind === 'gateway_rule') grouped.gatewayRules.push(item);
                    else if (row.EvidenceKind === 'access_policy') grouped.accessPolicies.push(item);
                    else if (row.EvidenceKind === 'access_log') grouped.accessLogs.push(item);
                    else if (row.EvidenceKind === 'dlp_profile') grouped.dlpProfiles.push(item);
                    else if (row.EvidenceKind === 'warp_profile') grouped.warpProfiles.push(item);
                    else if (row.EvidenceKind === 'virtual_network') grouped.virtualNetworks.push(item);
                    else if (row.EvidenceKind === 'gateway_app_type') grouped.gatewayAppTypes.push(item);
                    else if (row.EvidenceKind === 'permission_family') grouped.permissionMatrix.push(item);
                    else if (row.EvidenceKind === 'audit_log') grouped.auditLogs.push(item);
                    else if (row.EvidenceKind === 'account_log') grouped.accountLogs.push(item);
                    else if (row.EvidenceKind === 'security_insight') grouped.securityInsights.push(item);
                    else if (row.EvidenceKind === 'appsec_report') grouped.applicationSecurityReports.push(item);
                    else if (row.EvidenceKind === 'api_gateway_operation') grouped.apiGatewayOperations.push(item);
                    else if (row.EvidenceKind === 'casb_finding') grouped.casbFindings.push(item);
                    else if (row.EvidenceKind === 'tunnel') grouped.tunnels.push(item);
                    else if (row.EvidenceKind === 'cloudforce_one') grouped.cloudforceRequests.push(item);
                    else if (row.EvidenceKind === 'intel_feed') grouped.intelFeeds.push(item);
                    else if (row.EvidenceKind === 'dns_firewall') grouped.dnsFirewallRules.push(item);
                    else if (row.EvidenceKind === 'load_balancer_pool') grouped.loadBalancerPools.push(item);
                    else if (row.EvidenceKind === 'load_balancer_monitor') grouped.loadBalancerMonitors.push(item);
                    else if (row.EvidenceKind === 'magic_wan_site') grouped.magicWanSites.push(item);
                    else if (row.EvidenceKind === 'magic_wan_route') grouped.magicWanRoutes.push(item);
                    else if (row.EvidenceKind === 'mtls_certificate') grouped.mtlsCertificates.push(item);
                    else if (row.EvidenceKind === 'access_group') grouped.accessGroups.push(item);
                    else if (row.EvidenceKind === 'access_organization') grouped.accessOrganizations.push(item);
                    else if (row.EvidenceKind === 'access_certificate') grouped.accessCertificates.push(item);
                    else if (row.EvidenceKind === 'warp_connector') grouped.warpConnectors.push(item);
                    else if (row.EvidenceKind === 'network_route') grouped.teamnetRoutes.push(item);
                    else if (row.EvidenceKind === 'teams_dex_test') grouped.teamsDexTests.push(item);
                });
                return {
                    records: snapshots,
                    notConfigured: false,
                    metrics: dashboardMetrics,
                    dashboardSourceMetrics: dashboardMetrics,
                    sourceLineage: {
                        sourceKey: 'cloudflare_network_security',
                        sourceBuilder: 'storedStackCTRLNetworkEvidence',
                        sourceLayer: 'StackCTRLNetworkEvidenceSnapshots + StackCTRLNetworkEvidence',
                        evidenceSnapshotId: snapshot.ID,
                        collectedAt: snapshot.CollectedAt,
                        sourceFetchedAt: snapshot.SourceFetchedAt,
                        sourceEndpoint: snapshot.SourceEndpoint,
                        collectionTrigger: snapshot.CollectionTrigger,
                        collectionStatus: snapshot.CollectionStatus,
                        isComplete: Boolean(Number(snapshot.IsComplete)),
                        evidenceRecordCount: Number(snapshot.EvidenceRecordCount),
                        omittedRecordCount: Number(snapshot.OmittedRecordCount)
                    },
                    evidence: Object.entries(grouped).map(([evidenceType, data]) => ({ evidenceType, data })),
                    warnings: [],
                    rawReference: { table: this.table, recordId: snapshot.ID }
                };
            }
            const rows = await queryRows(
                pool,
                `SELECT snapshot.ID, snapshot.CreatedAt,
                        JSON_EXTRACT(snapshot.MetricsJson, '$.cloudflare_network_security') AS CloudflareMetricsJson,
                        JSON_EXTRACT(snapshot.SourceFreshnessJson, '$.cloudflare_network_security') AS CloudflareFreshnessJson
                 FROM StackCTRLTenantEvidenceSnapshots snapshot
                 WHERE snapshot.ID = (
                    SELECT MAX(latest.ID)
                    FROM StackCTRLTenantEvidenceSnapshots latest
                    WHERE latest.CompanyID = ?
                 )
                 LIMIT 1`,
                [companyId]
            );
            const snapshot = rows[0];
            const metrics = snapshot?.CloudflareMetricsJson || {};
            const freshness = snapshot?.CloudflareFreshnessJson || {};
            if (!snapshot || !Object.keys(metrics).length) return { records: [], metrics: {}, evidence: [] };
            return {
                records: [{
                    ID: snapshot.ID,
                    ...metrics,
                    LastUpdated: freshness.lastUpdated || snapshot.CreatedAt
                }],
                metrics,
                evidence: [{
                    evidenceType: 'cached_cloudflare_metrics',
                    data: metrics
                }],
                rawReference: { table: 'StackCTRLTenantEvidenceSnapshots', recordId: snapshot.ID }
            };
        },
        fromRefresh(refreshed, stored) {
            const overview = refreshed?.overview || {};
            const accessLogs = Array.isArray(refreshed?.accessLogs) ? refreshed.accessLogs : [];
            const apps = Array.isArray(refreshed?.apps) ? refreshed.apps : [];
            const devices = Array.isArray(refreshed?.devices) ? refreshed.devices : [];
            const deniedAccessEvents = accessLogs.filter(event => ['block', 'blocked', 'deny', 'denied']
                .includes(String(event?.action || event?.decision || event?.status || '').toLowerCase())).length;
            const metrics = {
                ...overview,
                protectedApps: Number(overview.protectedApps ?? apps.length ?? 0),
                enrolledDevices: Number(overview.enrolledDevices ?? devices.length ?? 0),
                recentAccessEvents: accessLogs.length,
                deniedAccessEvents
            };
            const fetchedAt = refreshed?.fetchedAt || new Date().toISOString();
            return {
                records: [{ ...metrics, LastUpdated: fetchedAt }],
                notConfigured: false,
                metrics,
                dashboardSourceMetrics: metrics,
                sourceLineage: {
                    sourceKey: 'cloudflare_network_security',
                    sourceBuilder: 'liveCloudflareDashboardRefresh',
                    sourceLayer: 'Cloudflare dashboard API',
                    collectionStatus: refreshed?.success === false ? 'partial' : 'complete',
                    sourceFetchedAt: fetchedAt
                },
                evidence: [{
                    evidenceType: 'live_cloudflare_dashboard',
                    data: { ...refreshed, overview, apps, devices, accessLogs, sections: refreshed?.sections || {} }
                }],
                warnings: [...(stored?.warnings || []), ...(refreshed?.warnings || [])],
                rawReference: { table: this.table, recordId: null }
            };
        },
        metrics: records => summaryMetrics(records[0]),
        evidence: records => records
    },
    duo_licences: {
        table: 'client_duo_stats',
        async load(pool, companyId) {
            const records = await queryRows(pool, `SELECT DISTINCT cds.id, cds.used_licenses, cds.total_licenses,
                                                           cds.edition, cds.last_updated, cds.status
                                                    FROM client_duo_stats cds
                                                    INNER JOIN user_duo_accounts uda ON uda.duo_id = cds.id
                                                    INNER JOIN Users u ON u.ID = uda.user_id
                                                    WHERE u.CompanyID = ?`, [companyId]);
            const totals = records.reduce((value, row) => {
                value.usedLicences += Number(row.used_licenses || 0);
                value.totalLicences += Number(row.total_licenses || 0);
                return value;
            }, { accounts: records.length, usedLicences: 0, totalLicences: 0 });
            totals.remainingLicences = Math.max(0, totals.totalLicences - totals.usedLicences);
            return { records, notConfigured: !records.length, metrics: totals, evidence: records };
        },
        metrics: () => ({}),
        evidence: records => records
    },
    billing: {
        table: 'Invoices',
        async load(pool, companyId) {
            const records = await queryRows(pool, 'SELECT * FROM Invoices WHERE CompanyID = ? ORDER BY InvoiceDate DESC LIMIT 250', [companyId]);
            const unpaid = records.filter(row => ['unpaid', 'overdue'].includes(String(row.Status || '').toLowerCase()));
            const total = rowsTotal(records);
            const outstanding = rowsTotal(unpaid);
            return {
                records,
                metrics: { invoiceCount: records.length, unpaidInvoiceCount: unpaid.length, invoicedTotal: total, outstandingTotal: outstanding },
                evidence: records
            };
        },
        metrics: () => ({}),
        evidence: records => records
    },
    projects: {
        table: 'Projects',
        async load(pool, companyId) {
            const records = await queryRows(pool, 'SELECT * FROM Projects WHERE CompanyID = ? ORDER BY ProjectID DESC LIMIT 250', [companyId]);
            const statusCounts = records.reduce((counts, row) => {
                const status = String(row.Status || 'unknown').toLowerCase();
                counts[status] = (counts[status] || 0) + 1;
                return counts;
            }, {});
            return { records, metrics: { projectCount: records.length, statusCounts }, evidence: records };
        },
        metrics: () => ({}),
        evidence: records => records
    }
};

function payloadDefinition(table) {
    return {
        table,
        async load(pool, companyId) {
            const records = await queryRows(pool, `SELECT * FROM ${table} WHERE CompanyID = ? ORDER BY LastUpdated DESC LIMIT 1`, [companyId]);
            const payload = extractPayload(records[0]);
            return { records, metrics: summaryMetrics(payload), evidence: payload ? [payload] : [] };
        },
        metrics: records => summaryMetrics(extractPayload(records[0])),
        evidence: records => records
    };
}

function rowsTotal(rows) {
    return Number(rows.reduce((sum, row) => sum + Number(row.TotalAmount || row.total || 0), 0).toFixed(2));
}

async function runSourceAdapter(context) {
    const definition = definitions[context.capability.sourceKey];
    if (!definition) {
        return statusResult(context.capability, 'error', {
            warnings: [`No StackCTRL source adapter is registered for ${context.capability.sourceKey}.`]
        });
    }
    try {
        return await collectSource(context, definition);
    } catch (error) {
        return statusResult(context.capability, 'error', {
            warnings: [`${context.capability.displayName} adapter failed.`],
            errorMessage: error.message
        });
    }
}

async function identityAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'identity' } }); }
async function devicesAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'devices' } }); }
async function emailSecurityAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'email_security' } }); }
async function securityAlertsAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'security_alerts' } }); }
async function backupAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'backup' } }); }
async function applicationsAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'applications' } }); }
async function governanceAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'governance' } }); }
async function complianceAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'compliance' } }); }
async function operationsAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'operations' } }); }
async function cloudflareNetworkSecurityAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'cloudflare_network_security' } }); }
async function duoLicencesAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'duo_licences' } }); }
async function billingAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'billing' } }); }
async function projectsAdapter(context) { return runSourceAdapter({ ...context, capability: { ...context.capability, sourceKey: 'projects' } }); }

const SOURCE_ADAPTERS = {
    identity: identityAdapter,
    devices: devicesAdapter,
    email_security: emailSecurityAdapter,
    security_alerts: securityAlertsAdapter,
    backup: backupAdapter,
    applications: applicationsAdapter,
    governance: governanceAdapter,
    compliance: complianceAdapter,
    operations: operationsAdapter,
    cloudflare_network_security: cloudflareNetworkSecurityAdapter,
    duo_licences: duoLicencesAdapter,
    billing: billingAdapter,
    projects: projectsAdapter
};

module.exports = {
    SOURCE_ADAPTERS,
    runSourceAdapter,
    refreshWithDeadline,
    identityAdapter,
    devicesAdapter,
    emailSecurityAdapter,
    securityAlertsAdapter,
    backupAdapter,
    applicationsAdapter,
    governanceAdapter,
    complianceAdapter,
    operationsAdapter,
    cloudflareNetworkSecurityAdapter,
    duoLicencesAdapter,
    billingAdapter,
    projectsAdapter
};
