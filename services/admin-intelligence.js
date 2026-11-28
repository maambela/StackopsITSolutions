const { logicalContextBytesSql } = require('./intelligence/tenant-snapshot-storage');

function parseJson(value, fallback = null) {
    if (value == null) return fallback;
    if (Buffer.isBuffer(value)) value = value.toString('utf8');
    if (typeof value === 'object') return value;
    try {
        return JSON.parse(value);
    } catch (_) {
        return fallback;
    }
}

function normalizeRow(row) {
    if (!row) return null;
    const normalized = { ...row };
    for (const key of [
        'RequestedOutputTypes', 'ContentJson', 'TokenUsageJson', 'ConfigurationJson',
        'WarningsJson', 'MetricsJson', 'SourceFreshnessJson', 'CompactContextJson'
    ]) {
        if (Object.prototype.hasOwnProperty.call(normalized, key)) {
            normalized[key] = parseJson(normalized[key], normalized[key]);
        }
    }
    return normalized;
}

function createAdminIntelligenceService({
    pool,
    azureOpenAI,
    intelligenceService,
    schedulerService,
    automationService = null,
    defaultOutputTypes = [],
    logger = console
} = {}) {
    if (!pool || !azureOpenAI || !intelligenceService || !schedulerService) {
        throw new Error('Admin Intelligence requires database, Azure, intelligence, and scheduler services');
    }

    function auditAction(action, companyId, user) {
        logger.log('[StackCTRL Admin Intelligence] Action requested.', {
            action,
            companyId: Number(companyId),
            userId: user?.id || user?.userId || null,
            email: user?.email || null
        });
    }

    async function optionalQuery(label, sql, params = []) {
        try {
            return await pool.query(sql, params);
        } catch (error) {
            logger.error(`[StackCTRL Admin Intelligence] ${label} is unavailable:`, error.message);
            return [[]];
        }
    }

    async function getRunMetrics() {
        try {
            const [[dailyRows], [rateLimitedRows]] = await Promise.all([
                pool.query(
                    `SELECT COUNT(*) AS TotalRunsToday,
                            SUM(Status = 'completed') AS CompletedRunsToday,
                            SUM(Status = 'failed') AS FailedRunsToday,
                            SUM(Status = 'rate_limited' OR RetryCount > 0) AS RateLimitedRunsToday,
                            COALESCE(SUM(InputTokens), 0) AS InputTokensToday,
                            COALESCE(SUM(OutputTokens), 0) AS OutputTokensToday,
                            COALESCE(SUM(TotalTokens), 0) AS TotalTokensToday,
                            AVG(RequestSizeBytes) AS AverageRequestSize,
                            AVG(ResponseSizeBytes) AS AverageResponseSize
                     FROM StackCTRLIntelligenceRuns
                     WHERE StartedAt >= CURDATE()`
                ),
                pool.query(
                    `SELECT COUNT(*) AS CurrentRateLimitedRuns
                     FROM StackCTRLIntelligenceRuns
                     WHERE Status = 'rate_limited'`
                )
            ]);
            return { ...normalizeRow(dailyRows[0]), ...normalizeRow(rateLimitedRows[0]), metadataAvailable: true };
        } catch (error) {
            if (error?.code !== 'ER_BAD_FIELD_ERROR') throw error;
            const [rows] = await pool.query(
                `SELECT COUNT(*) AS TotalRunsToday,
                        SUM(Status = 'completed') AS CompletedRunsToday,
                        SUM(Status = 'failed') AS FailedRunsToday
                 FROM StackCTRLIntelligenceRuns
                 WHERE StartedAt >= CURDATE()`
            );
            return {
                ...normalizeRow(rows[0]),
                RateLimitedRunsToday: 0,
                CurrentRateLimitedRuns: 0,
                InputTokensToday: 0,
                OutputTokensToday: 0,
                TotalTokensToday: 0,
                AverageRequestSize: null,
                AverageResponseSize: null,
                metadataAvailable: false
            };
        }
    }

    async function getSystemStatus() {
        const [azure, latestCompleted, latestFailed, latestRun, usage] = await Promise.all([
            azureOpenAI.getSafeConfiguration(),
            pool.query(`SELECT * FROM StackCTRLIntelligenceRuns FORCE INDEX (PRIMARY) WHERE Status = 'completed' ORDER BY ID DESC LIMIT 1`),
            pool.query(`SELECT * FROM StackCTRLIntelligenceRuns FORCE INDEX (PRIMARY) WHERE Status = 'failed' ORDER BY ID DESC LIMIT 1`),
            pool.query('SELECT * FROM StackCTRLIntelligenceRuns FORCE INDEX (PRIMARY) ORDER BY ID DESC LIMIT 1'),
            getRunMetrics()
        ]);
        return {
            azure,
            latestSuccessfulRun: normalizeRow(latestCompleted[0][0]),
            latestFailedRun: normalizeRow(latestFailed[0][0]),
            latestRun: normalizeRow(latestRun[0][0]),
            latestErrorMessage: latestFailed[0][0]?.ErrorMessage || null,
            lastRetryCount: Number(latestRun[0][0]?.RetryCount || 0),
            usage,
            serverAutomation: automationService?.getStatus?.() || null
        };
    }

    function capabilitySummary(rows) {
        const expected = rows.filter(row => Number(row.IsExpected) === 1);
        return {
            profileKey: rows.find(row => row.ProfileKey)?.ProfileKey || 'standard',
            totalSources: rows.length,
            expectedSources: expected.length,
            enabledSources: rows.filter(row => Number(row.IsEnabled) === 1).length,
            expectedSourceKeys: expected.map(row => row.SourceKey)
        };
    }

    async function getTenants() {
        const [companiesResult, capabilitiesResult, snapshotsResult] = await Promise.all([
            pool.query('SELECT ID, CompanyName FROM Companies ORDER BY CompanyName LIMIT 500'),
            pool.query('SELECT CompanyID, ProfileKey, SourceKey, IsExpected, IsEnabled FROM StackCTRLClientCapabilities'),
            pool.query(
                `SELECT CompanyID, TenantKey, ID AS SnapshotID, CreatedAt
                 FROM StackCTRLTenantEvidenceSnapshots
                 WHERE ID IN (
                    SELECT MAX(ID) FROM StackCTRLTenantEvidenceSnapshots GROUP BY CompanyID
                 )`
            )
        ]);
        const capabilities = new Map();
        for (const row of capabilitiesResult[0]) {
            if (!capabilities.has(row.CompanyID)) capabilities.set(row.CompanyID, []);
            capabilities.get(row.CompanyID).push(row);
        }
        const snapshots = new Map(snapshotsResult[0].map(row => [row.CompanyID, row]));
        return companiesResult[0].map(company => ({
            companyId: company.ID,
            companyName: company.CompanyName,
            tenantKey: snapshots.get(company.ID)?.TenantKey || `company-${company.ID}`,
            latestSnapshotId: snapshots.get(company.ID)?.SnapshotID || null,
            latestSnapshotAt: snapshots.get(company.ID)?.CreatedAt || null,
            capabilities: capabilitySummary(capabilities.get(company.ID) || [])
        }));
    }

    async function readinessRow(tableName, companyId) {
        try {
            const [rows] = await pool.query(
                `SELECT COUNT(*) AS RecordCount, MAX(CreatedAt) AS LatestUpdatedAt
                 FROM ${tableName} WHERE CompanyID = ?`,
                [companyId]
            );
            return { tableName, available: true, ...normalizeRow(rows[0]) };
        } catch (error) {
            if (error?.code === 'ER_BAD_FIELD_ERROR') {
                const [rows] = await pool.query(`SELECT COUNT(*) AS RecordCount FROM ${tableName} WHERE CompanyID = ?`, [companyId]);
                return { tableName, available: true, ...normalizeRow(rows[0]), LatestUpdatedAt: null };
            }
            if (error?.code === 'ER_NO_SUCH_TABLE') return { tableName, available: false, RecordCount: 0, LatestUpdatedAt: null };
            throw error;
        }
    }

    async function safeReadinessRow(tableName, companyId) {
        try {
            return await readinessRow(tableName, companyId);
        } catch (error) {
            logger.error(`[StackCTRL Admin Intelligence] ${tableName} readiness is unavailable:`, error.message);
            return { tableName, available: false, RecordCount: 0, LatestUpdatedAt: null, errorMessage: error.message };
        }
    }

    async function getTenant(companyId) {
        const numericCompanyId = Number(companyId);
        const [companyRows] = await pool.query('SELECT ID, CompanyName FROM Companies WHERE ID = ? LIMIT 1', [numericCompanyId]);
        if (!companyRows.length) {
            const error = new Error('Company not found');
            error.statusCode = 404;
            throw error;
        }

        const [snapshotRows] = await pool.query(
            `SELECT ID, CompanyID, TenantKey, SnapshotType, DataCompletenessScore, CreatedAt,
                    OCTET_LENGTH(ContextJson) AS ContextSizeBytes,
                    ${logicalContextBytesSql} AS LogicalContextSizeBytes
             FROM StackCTRLTenantEvidenceSnapshots
             WHERE ID = (SELECT MAX(ID) FROM StackCTRLTenantEvidenceSnapshots WHERE CompanyID = ?)
             LIMIT 1`,
            [numericCompanyId]
        );
        const snapshot = normalizeRow(snapshotRows[0]);
        const { LogicalContextSizeBytes, ...snapshotMetadata } = snapshot || {};
        const snapshotId = snapshot?.ID || 0;
        const readinessTables = [
            'StackCTRLTenantAIOutputs',
            'StackCTRLTenantRiskRegister',
            'StackCTRLTenantRecommendations',
            'StackCTRLTenantTrendAnalysis',
            'StackCTRLIntelligenceMetrics',
            'StackCTRLIntelligenceSourceStatus',
            'StackCTRLCompactIntelligenceContexts',
            'StackCTRLIntelligencePeriods'
        ];

        const [sourceRows, runRows, outputRows, riskRows, recommendationRows, trendRows, capabilityRows, compactRows, periodRows, historicalRows, readiness] = await Promise.all([
            snapshotId
                ? optionalQuery('Source status rows', 'SELECT * FROM StackCTRLIntelligenceSourceStatus WHERE SnapshotID = ? ORDER BY SourceKey', [snapshotId])
                : Promise.resolve([[]]),
            optionalQuery('Intelligence run rows', 'SELECT * FROM StackCTRLIntelligenceRuns FORCE INDEX (PRIMARY) WHERE CompanyID = ? ORDER BY ID DESC LIMIT 50', [numericCompanyId]),
            optionalQuery('AI output rows', 'SELECT * FROM StackCTRLTenantAIOutputs FORCE INDEX (PRIMARY) WHERE CompanyID = ? ORDER BY ID DESC LIMIT 50', [numericCompanyId]),
            optionalQuery('Risk register rows', 'SELECT * FROM StackCTRLTenantRiskRegister FORCE INDEX (PRIMARY) WHERE CompanyID = ? ORDER BY ID DESC LIMIT 20', [numericCompanyId]),
            optionalQuery('Recommendation rows', 'SELECT * FROM StackCTRLTenantRecommendations FORCE INDEX (PRIMARY) WHERE CompanyID = ? ORDER BY ID DESC LIMIT 20', [numericCompanyId]),
            optionalQuery('Trend rows', 'SELECT * FROM StackCTRLTenantTrendAnalysis FORCE INDEX (PRIMARY) WHERE CompanyID = ? ORDER BY ID DESC LIMIT 20', [numericCompanyId]),
            optionalQuery('Capability rows', 'SELECT * FROM StackCTRLClientCapabilities WHERE CompanyID = ?', [numericCompanyId]),
            snapshotId
                ? optionalQuery('Compact context rows',
                    `SELECT ID, CompanyID, SnapshotID, PeriodType, PeriodStart, PeriodEnd,
                            CompactContextSizeBytes, EvidenceIncludedCount, EvidenceOmittedCount, CreatedAt
                     FROM StackCTRLCompactIntelligenceContexts FORCE INDEX (PRIMARY)
                     WHERE CompanyID = ? AND SnapshotID = ? ORDER BY ID DESC LIMIT 20`,
                    [numericCompanyId, snapshotId]
                )
                : Promise.resolve([[]]),
            optionalQuery('Period intelligence rows',
                `SELECT * FROM StackCTRLIntelligencePeriods FORCE INDEX (PRIMARY)
                 WHERE CompanyID = ? ORDER BY ID DESC LIMIT 100`,
                [numericCompanyId]
            ),
            snapshotId
                ? optionalQuery('Historical comparison rows',
                    `SELECT ComparisonKey, AvailabilityStatus, BaselineSnapshotID, BaselineCreatedAt,
                            TargetAt, DifferenceMinutes
                     FROM StackCTRLIntelligenceHistoricalComparisons FORCE INDEX (PRIMARY)
                     WHERE CompanyID = ? AND CurrentSnapshotID = ?
                     ORDER BY ID DESC LIMIT 20`,
                    [numericCompanyId, snapshotId]
                )
                : Promise.resolve([[]]),
            Promise.all(readinessTables.map(table => safeReadinessRow(table, numericCompanyId)))
        ]);
        const sources = sourceRows[0].map(normalizeRow);
        const expectedSources = sources.filter(source => Number(source.IsExpected) === 1);
        const availableSources = expectedSources.filter(source => ['available', 'stale'].includes(source.Status));

        return {
            company: {
                companyId: companyRows[0].ID,
                companyName: companyRows[0].CompanyName,
                tenantKey: snapshot?.TenantKey || `company-${numericCompanyId}`,
                capabilities: capabilitySummary(capabilityRows[0])
            },
            latestSnapshot: snapshot ? {
                ...snapshotMetadata,
                expectedSources: expectedSources.length,
                availableSources: availableSources.length,
                missingSources: expectedSources.filter(source => ['missing', 'not_configured', 'error'].includes(source.Status)).length,
                staleSources: expectedSources.filter(source => source.Status === 'stale').length,
                notExpectedSources: sources.filter(source => source.Status === 'not_expected').length
            } : null,
            sourceStatuses: sources,
            runs: runRows[0].map(normalizeRow),
            outputs: outputRows[0].map(normalizeRow),
            risks: riskRows[0].map(normalizeRow),
            recommendations: recommendationRows[0].map(normalizeRow),
            trends: trendRows[0].map(normalizeRow),
            compactContexts: compactRows[0].map(row => {
                const normalized = normalizeRow(row);
                const fullSize = Number(LogicalContextSizeBytes || 0);
                return {
                    ...normalized,
                    FullContextSizeBytes: fullSize,
                    ReductionPercentage: fullSize
                        ? Number((100 - ((Number(normalized.CompactContextSizeBytes || 0) / fullSize) * 100)).toFixed(2))
                        : null
                };
            }),
            periods: periodRows[0].map(normalizeRow),
            historicalAvailability: Object.fromEntries(historicalRows[0].map(row => [row.ComparisonKey, {
                availability: row.AvailabilityStatus,
                baselineSnapshotId: row.BaselineSnapshotID,
                baselineCreatedAt: row.BaselineCreatedAt,
                targetAt: row.TargetAt,
                differenceMinutes: row.DifferenceMinutes
            }])),
            powerBIReadiness: readiness
        };
    }

    async function createSnapshot(companyId, user) {
        auditAction('create_snapshot', companyId, user);
        return intelligenceService.bootstrap({ companyId: Number(companyId), user });
    }

    async function latestSnapshotId(companyId, requestedSnapshotId = null) {
        let snapshotId = Number(requestedSnapshotId || 0);
        if (snapshotId) return snapshotId;
        const [rows] = await pool.query(
            'SELECT MAX(ID) AS SnapshotID FROM StackCTRLTenantEvidenceSnapshots WHERE CompanyID = ?',
            [Number(companyId)]
        );
        return Number(rows[0]?.SnapshotID || 0);
    }

    function summarizeHistoricalContext(context) {
        return Object.fromEntries(Object.entries(context?.comparisons || {}).map(([key, value]) => [key, {
            availability: value.availability,
            snapshotId: value.snapshot?.snapshotId || null,
            targetAt: value.targetAt,
            differenceMinutes: value.differenceMinutes
        }]));
    }

    async function buildCompactContext(companyId, options, user) {
        auditAction('build_compact_context', companyId, user);
        const snapshotId = await latestSnapshotId(companyId, options?.snapshotId);
        if (!snapshotId) {
            const error = new Error('Create a snapshot before building a compact context');
            error.statusCode = 400;
            throw error;
        }
        const historicalContext = await schedulerService.getHistoricalSnapshotContext(Number(companyId), snapshotId);
        const compact = await intelligenceService.buildCompactContext({
            companyId: Number(companyId),
            snapshotId,
            periodType: options?.periodType || 'snapshot',
            historicalContext
        });
        return {
            compactContextId: compact.compactContextId,
            snapshotId,
            periodType: compact.periodType,
            fullContextSizeBytes: compact.fullContextSizeBytes,
            compactContextSizeBytes: compact.compactContextSizeBytes,
            reductionPercentage: compact.reductionPercentage,
            evidenceIncludedCount: compact.evidenceIncludedCount,
            evidenceOmittedCount: compact.evidenceOmittedCount,
            historicalAvailability: compact.historicalAvailability
        };
    }

    async function runAnalysis(companyId, options, user) {
        const analysisMode = String(options?.analysisMode || 'compact').toLowerCase();
        auditAction(`run_${analysisMode}_analysis`, companyId, user);
        const snapshotId = await latestSnapshotId(companyId, options?.snapshotId);
        if (!snapshotId) {
            const error = new Error('Create a snapshot before running Azure analysis');
            error.statusCode = 400;
            throw error;
        }
        const outputTypes = Array.isArray(options?.outputTypes) && options.outputTypes.length
            ? options.outputTypes
            : defaultOutputTypes;
        if (analysisMode === 'compact') {
            const historicalContext = await schedulerService.getHistoricalSnapshotContext(Number(companyId), snapshotId);
            const periodResult = await intelligenceService.runPeriodIntelligence({
                companyId: Number(companyId),
                snapshotId,
                outputTypes,
                periodType: 'daily',
                historicalContext,
                user
            });
            return {
                ...periodResult.analysis,
                period: periodResult.period,
                compactContext: periodResult.compactContext,
                historicalAvailability: summarizeHistoricalContext(historicalContext)
            };
        }
        const historicalContext = await schedulerService.getHistoricalSnapshotContext(Number(companyId), snapshotId);
        const result = await intelligenceService.analyseSnapshot({
            companyId: Number(companyId),
            snapshotId,
            outputTypes,
            user,
            historicalContext,
            analysisMode
        });
        return {
            ...result,
            historicalAvailability: summarizeHistoricalContext(historicalContext)
        };
    }

    async function runFullTest(companyId, options, user) {
        auditAction('run_full_test', companyId, user);
        return schedulerService.runNow({
            companyId: Number(companyId),
            includeAnalysis: options?.includeAnalysis !== false,
            outputTypes: Array.isArray(options?.outputTypes) && options.outputTypes.length
                ? options.outputTypes
                : defaultOutputTypes,
            user
        });
    }

    async function runPeriod(companyId, periodType, options, user) {
        auditAction(`run_${periodType}_intelligence`, companyId, user);
        const snapshotId = await latestSnapshotId(companyId, options?.snapshotId);
        if (!snapshotId) {
            const error = new Error('Create a snapshot before running period intelligence');
            error.statusCode = 400;
            throw error;
        }
        const historicalContext = await schedulerService.getHistoricalSnapshotContext(Number(companyId), snapshotId);
        return intelligenceService.runPeriodIntelligence({
            companyId: Number(companyId),
            snapshotId,
            periodType,
            historicalContext,
            outputTypes: options?.outputTypes,
            user
        });
    }

    return {
        getSystemStatus,
        getTenants,
        getTenant,
        createSnapshot,
        buildCompactContext,
        runAnalysis,
        runFullTest,
        runPeriod
    };
}

module.exports = { createAdminIntelligenceService };
