const { loadClientCapabilities } = require('./intelligence/capabilities');
const { SOURCE_ADAPTERS } = require('./intelligence/source-adapters');
const { buildDashboardIntelligenceContexts } = require('./intelligence/dashboard-context');
const { buildRiskEngine } = require('./intelligence/risk-engine');
const { DateTime } = require('luxon');
const { buildCompactIntelligenceContext, sizeBytes } = require('./intelligence/compact-context-builder');

const ALLOWED_OUTPUT_TYPES = new Set([
    'executive_summary',
    'governance_assessment',
    'compliance_review',
    'risk_register',
    'recommendations',
    'trend_analysis',
    'board_report',
    'overall_risk_score',
    'risk_level',
    'powerbi_summary'
]);

const OUTPUT_TITLES = {
    executive_summary: 'Executive Summary',
    governance_assessment: 'Governance Assessment',
    compliance_review: 'Compliance Review',
    risk_register: 'Risk Register',
    recommendations: 'Recommendations',
    trend_analysis: 'Trend Analysis',
    board_report: 'Board Report',
    overall_risk_score: 'Overall Risk Score',
    risk_level: 'Risk Level',
    powerbi_summary: 'Power BI Summary'
};

const SYSTEM_PROMPT = `You are StackCTRL Intelligence, an enterprise technology risk and governance analyst.
StackCTRL-calculated tenant evidence is the primary source of truth. Use external/grounding knowledge only to interpret risk, best practices, and recommendations.
Analyse only the frozen StackCTRL snapshot supplied in the request. Never call, request, or imply direct access to Microsoft Graph, Cloudflare, Duo, or another vendor API.
Do not invent tenant facts. Clearly identify stale, missing, partial, or not-expected evidence. Return valid JSON only.`;

const PROMPT_VERSION = 'stackctrl-intelligence-v2';
const INTELLIGENCE_TIME_ZONE = 'Africa/Johannesburg';

const PERIOD_OUTPUT_TYPES = {
    daily: [
        'powerbi_summary',
        'executive_summary',
        'board_report',
        'risk_register',
        'recommendations',
        'trend_analysis',
        'compliance_review',
        'governance_assessment',
        'risk_level',
        'overall_risk_score'
    ],
    weekly: ['executive_summary', 'board_report', 'risk_register', 'recommendations', 'trend_analysis', 'overall_risk_score', 'risk_level', 'powerbi_summary'],
    monthly: ['executive_summary', 'governance_assessment', 'compliance_review', 'trend_analysis', 'risk_register', 'recommendations', 'overall_risk_score', 'risk_level', 'powerbi_summary'],
    yearly: ['executive_summary', 'board_report', 'governance_assessment', 'compliance_review', 'trend_analysis', 'risk_register', 'recommendations', 'overall_risk_score', 'risk_level', 'powerbi_summary']
};
const PERIOD_ROLLUP_TYPES = { weekly: 'daily', monthly: 'weekly', yearly: 'monthly' };

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

function normalizeStoredRow(row) {
    if (!row) return null;
    return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, parseJsonValue(value)]));
}

function getLastUpdated(row) {
    if (!row) return null;
    return row.LastUpdated || row.last_updated || row.UpdatedAt || row.updated_at || row.CreatedAt || null;
}

function isMissingTableError(error) {
    return ['ER_NO_SUCH_TABLE', 'ER_BAD_FIELD_ERROR'].includes(error?.code);
}

function toDateOrNull(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function toNullableNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
}

function toNullableDate(value) {
    const date = toDateOrNull(value);
    return date ? date.toISOString().slice(0, 10) : null;
}

function toNullableText(value) {
    if (value === null || value === undefined || value === '') return null;
    return String(value);
}

function normalizePowerBISummary(value, analysis = {}, stackctrl = {}) {
    const summary = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const risk = stackctrl.riskEngine || {};
    const metrics = stackctrl.metrics || {};
    const cloudflareSource = Array.isArray(stackctrl.sources)
        ? stackctrl.sources.find(source => source.sourceKey === 'cloudflare_network_security')
        : null;
    const topRiskDomain = Object.entries(risk.domainRiskScores || {})
        .filter(([, score]) => Number.isFinite(Number(score)))
        .sort((left, right) => Number(right[1]) - Number(left[1]))[0]?.[0] || null;
    return {
        risk_score: toNullableNumber(risk.overallRiskScore ?? summary.risk_score ?? analysis.overall_risk_score),
        risk_level: toNullableText(risk.overallRiskLevel ?? summary.risk_level ?? analysis.risk_level),
        maturity_level: toNullableText(risk.securityMaturityLevel ?? summary.maturity_level),
        security_maturity_score: toNullableNumber(risk.securityMaturityScore ?? summary.security_maturity_score),
        top_risk_domain: toNullableText(summary.top_risk_domain ?? topRiskDomain),
        top_recommendation: toNullableText(summary.top_recommendation),
        mfa_coverage: toNullableNumber(metrics.identity?.mfaCoverage ?? summary.mfa_coverage),
        device_compliance: toNullableNumber(metrics.devices?.complianceRate ?? summary.device_compliance),
        high_severity_alerts: toNullableNumber(metrics.security_alerts?.highSeverityAlerts ?? summary.high_severity_alerts),
        cloudflare_status: toNullableText(cloudflareSource?.status ?? summary.cloudflare_status),
        data_completeness_score: toNullableNumber(stackctrl.dataCompleteness?.score ?? summary.data_completeness_score),
        security_health: toNullableNumber(risk.executiveKPIs?.securityHealth ?? summary.security_health),
        governance_health: toNullableNumber(risk.executiveKPIs?.governanceHealth ?? summary.governance_health),
        compliance_health: toNullableNumber(risk.executiveKPIs?.complianceHealth ?? summary.compliance_health),
        identity_health: toNullableNumber(risk.executiveKPIs?.identityHealth ?? summary.identity_health),
        device_health: toNullableNumber(risk.executiveKPIs?.deviceHealth ?? summary.device_health),
        email_health: toNullableNumber(risk.executiveKPIs?.emailHealth ?? summary.email_health),
        backup_health: toNullableNumber(risk.executiveKPIs?.backupHealth ?? summary.backup_health),
        operations_health: toNullableNumber(risk.executiveKPIs?.operationsHealth ?? summary.operations_health),
        applications_health: toNullableNumber(risk.executiveKPIs?.applicationsHealth ?? summary.applications_health),
        domain_risk_scores: risk.domainRiskScores || summary.domain_risk_scores || {}
    };
}

function flattenMetrics(value, prefix = '', depth = 0, output = []) {
    if (value === null || value === undefined) return output;
    if (depth > 3) {
        output.push({ name: prefix || 'value', type: 'json', jsonValue: value });
        return output;
    }
    if (Array.isArray(value)) {
        output.push({ name: prefix || 'value', type: 'json', jsonValue: value });
        return output;
    }
    if (typeof value === 'object') {
        for (const [key, nestedValue] of Object.entries(value)) {
            const name = prefix ? `${prefix}.${key}` : key;
            flattenMetrics(nestedValue, name, depth + 1, output);
        }
        return output;
    }
    if (typeof value === 'number') output.push({ name: prefix, type: 'number', numericValue: value });
    else if (typeof value === 'boolean') output.push({ name: prefix, type: 'boolean', booleanValue: value });
    else output.push({ name: prefix, type: 'text', textValue: String(value) });
    return output;
}

function getPeriodWindow(periodType, referenceDate = new Date()) {
    const type = String(periodType || '').toLowerCase();
    if (!PERIOD_OUTPUT_TYPES[type]) throw new Error('PeriodType must be daily, weekly, monthly, or yearly');
    const local = DateTime.fromJSDate(referenceDate instanceof Date ? referenceDate : new Date(referenceDate), {
        zone: 'utc'
    }).setZone(INTELLIGENCE_TIME_ZONE);
    const start = type === 'daily'
        ? local.startOf('day')
        : type === 'weekly'
            ? local.startOf('week')
            : type === 'monthly'
                ? local.startOf('month')
                : local.startOf('year');
    const end = type === 'daily'
        ? local.endOf('day')
        : type === 'weekly'
            ? local.endOf('week')
            : type === 'monthly'
                ? local.endOf('month')
                : local.endOf('year');
    return {
        periodType: type,
        periodStart: start.toUTC().toJSDate(),
        periodEnd: end.toUTC().toJSDate()
    };
}

function stackCTRLContextForAnalysis(analysisContext = {}) {
    if (analysisContext?.contextType !== 'stackctrl_compact_intelligence') {
        return analysisContext?.currentSnapshot?.context || analysisContext || {};
    }
    const riskScores = analysisContext.riskScores || {};
    return {
        riskEngine: {
            ...riskScores,
            executiveKPIs: analysisContext.healthKpis || riskScores.executiveKPIs || {}
        },
        executiveKPIs: analysisContext.healthKpis || {},
        metrics: analysisContext.dashboardCalculatedMetrics || {},
        sources: analysisContext.sourceSummary || [],
        dataCompleteness: analysisContext.dataCompleteness || {}
    };
}

function createStackCTRLIntelligenceService({ pool, azureOpenAI, refreshSource = null, logger = console } = {}) {
    if (!pool) throw new Error('StackCTRL Intelligence requires a database pool');
    if (!azureOpenAI) throw new Error('StackCTRL Intelligence requires Azure OpenAI');
    let runMetadataWarningShown = false;

    async function updateIntelligenceRun(executor, runId, runStatus, metadata = {}) {
        const tokenUsage = metadata.tokenUsage || metadata.usage || null;
        const inputTokens = toNullableNumber(tokenUsage?.input_tokens ?? tokenUsage?.inputTokens);
        const outputTokens = toNullableNumber(tokenUsage?.output_tokens ?? tokenUsage?.outputTokens);
        const totalTokens = toNullableNumber(tokenUsage?.total_tokens ?? tokenUsage?.totalTokens);
        const errorMessage = metadata.errorMessage
            ? String(metadata.errorMessage).slice(0, 5000)
            : null;
        try {
            await executor.query(
                `UPDATE StackCTRLIntelligenceRuns
                 SET Status = ?,
                     ModelName = COALESCE(?, ModelName),
                     AzureDeployment = COALESCE(?, AzureDeployment),
                     RequestSizeBytes = COALESCE(?, RequestSizeBytes),
                     ResponseSizeBytes = COALESCE(?, ResponseSizeBytes),
                     TokenUsageJson = COALESCE(?, TokenUsageJson),
                     InputTokens = COALESCE(?, InputTokens),
                     OutputTokens = COALESCE(?, OutputTokens),
                     TotalTokens = COALESCE(?, TotalTokens),
                     RetryCount = GREATEST(COALESCE(RetryCount, 0), ?),
                     LastRetryAt = CASE WHEN ? = 'rate_limited' THEN NOW() ELSE LastRetryAt END,
                     CompletedAt = CASE WHEN ? IN ('completed', 'failed') THEN NOW() ELSE CompletedAt END,
                     ErrorMessage = CASE WHEN ? = 'failed' THEN ? ELSE ErrorMessage END
                 WHERE ID = ?`,
                [
                    runStatus,
                    metadata.model || null,
                    metadata.deployment || null,
                    toNullableNumber(metadata.requestSizeBytes),
                    toNullableNumber(metadata.responseSizeBytes),
                    tokenUsage ? JSON.stringify(tokenUsage) : null,
                    inputTokens,
                    outputTokens,
                    totalTokens,
                    Math.max(0, Number(metadata.retryCount) || 0),
                    runStatus,
                    runStatus,
                    runStatus,
                    errorMessage,
                    runId
                ]
            );
        } catch (error) {
            if (error?.code !== 'ER_BAD_FIELD_ERROR') throw error;
            if (!runMetadataWarningShown) {
                runMetadataWarningShown = true;
                logger.warn('[StackCTRL Intelligence] Run metadata columns are not installed yet; storing status only.');
            }
            if (runStatus === 'completed') {
                await executor.query(
                    `UPDATE StackCTRLIntelligenceRuns
                     SET Status = 'completed', CompletedAt = NOW()
                     WHERE ID = ?`,
                    [runId]
                );
            } else if (runStatus === 'failed') {
                await executor.query(
                    `UPDATE StackCTRLIntelligenceRuns
                     SET Status = 'failed', CompletedAt = NOW(), ErrorMessage = ?
                     WHERE ID = ?`,
                    [errorMessage, runId]
                );
            } else {
                await executor.query('UPDATE StackCTRLIntelligenceRuns SET Status = ? WHERE ID = ?', [runStatus, runId]);
            }
        }
    }

    async function loadSnapshot(companyId, snapshotId = null) {
        const numericCompanyId = Number(companyId);
        const numericSnapshotId = Number(snapshotId || 0);
        const [rows] = numericSnapshotId
            ? await pool.query(
                'SELECT * FROM StackCTRLTenantEvidenceSnapshots WHERE ID = ? AND CompanyID = ? LIMIT 1',
                [numericSnapshotId, numericCompanyId]
            )
            : await pool.query(
                'SELECT * FROM StackCTRLTenantEvidenceSnapshots WHERE CompanyID = ? ORDER BY ID DESC LIMIT 1',
                [numericCompanyId]
            );
        if (!rows.length) throw new Error('Snapshot not found');
        return normalizeStoredRow(rows[0]);
    }

    async function buildCompactContext({
        companyId,
        snapshotId,
        periodType = 'snapshot',
        periodStart = null,
        periodEnd = null,
        historicalContext = null
    }) {
        const snapshot = await loadSnapshot(companyId, snapshotId);
        const rollupType = PERIOD_ROLLUP_TYPES[String(periodType).toLowerCase()];
        let periodRollups = [];
        if (rollupType && periodStart && periodEnd) {
            const [rows] = await pool.query(
                `SELECT ID, SnapshotID, PeriodType, PeriodStart, PeriodEnd, RiskScore, RiskLevel,
                        MaturityScore, IdentityHealth, DeviceHealth, EmailHealth, CloudflareHealth,
                        BackupHealth, GovernanceHealth, ComplianceHealth, ExecutiveSummary,
                        TopRisk, TopRecommendation, AzureOutputID, CreatedAt
                 FROM StackCTRLIntelligencePeriods
                 WHERE CompanyID = ? AND PeriodType = ? AND Status = 'completed'
                   AND PeriodStart >= ? AND PeriodStart <= ?
                 ORDER BY PeriodStart ASC, ID ASC LIMIT 400`,
                [Number(companyId), rollupType, toDateOrNull(periodStart), toDateOrNull(periodEnd)]
            );
            periodRollups = rows.map(normalizeStoredRow);
        }
        const compact = buildCompactIntelligenceContext({
            snapshot,
            historicalContext,
            periodRollups,
            periodType,
            periodStart,
            periodEnd
        });
        const [result] = await pool.query(
            `INSERT INTO StackCTRLCompactIntelligenceContexts
             (CompanyID, SnapshotID, PeriodType, PeriodStart, PeriodEnd,
              CompactContextJson, CompactContextSizeBytes, EvidenceIncludedCount,
              EvidenceOmittedCount)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                ID = LAST_INSERT_ID(ID),
                PeriodStart = VALUES(PeriodStart),
                PeriodEnd = VALUES(PeriodEnd),
                CompactContextJson = VALUES(CompactContextJson),
                CompactContextSizeBytes = VALUES(CompactContextSizeBytes),
                EvidenceIncludedCount = VALUES(EvidenceIncludedCount),
                EvidenceOmittedCount = VALUES(EvidenceOmittedCount),
                CreatedAt = CURRENT_TIMESTAMP`,
            [
                compact.companyId,
                compact.fullSnapshotId,
                compact.periodType,
                toDateOrNull(compact.periodStart),
                toDateOrNull(compact.periodEnd),
                JSON.stringify(compact.compactContextJson),
                compact.compactContextSizeBytes,
                compact.evidenceIncludedCount,
                compact.evidenceOmittedCount
            ]
        );
        const compactContextId = Number(result.insertId);
        const reductionPercentage = compact.fullContextSizeBytes > 0
            ? Number((100 - ((compact.compactContextSizeBytes / compact.fullContextSizeBytes) * 100)).toFixed(2))
            : null;
        return {
            ...compact,
            compactContextId,
            reductionPercentage,
            historicalAvailability: Object.fromEntries(
                Object.entries(compact.compactContextJson.historicalComparisons?.periods || {})
                    .map(([key, value]) => [key, value.availability])
            )
        };
    }

    async function getCompactContext({ companyId, snapshotId, periodType = null }) {
        const params = [Number(companyId), Number(snapshotId)];
        const periodFilter = periodType ? ' AND PeriodType = ?' : '';
        if (periodType) params.push(String(periodType));
        const [rows] = await pool.query(
            `SELECT * FROM StackCTRLCompactIntelligenceContexts
             WHERE CompanyID = ? AND SnapshotID = ?${periodFilter}
             ORDER BY ID DESC LIMIT 1`,
            params
        );
        if (!rows.length) return null;
        const row = normalizeStoredRow(rows[0]);
        const [snapshotRows] = await pool.query(
            `SELECT OCTET_LENGTH(ContextJson) AS FullContextSizeBytes
             FROM StackCTRLTenantEvidenceSnapshots WHERE ID = ? AND CompanyID = ? LIMIT 1`,
            [Number(snapshotId), Number(companyId)]
        );
        const fullContextSizeBytes = Number(snapshotRows[0]?.FullContextSizeBytes || 0);
        return {
            ...row,
            fullContextSizeBytes,
            reductionPercentage: fullContextSizeBytes
                ? Number((100 - ((Number(row.CompactContextSizeBytes || 0) / fullContextSizeBytes) * 100)).toFixed(2))
                : null
        };
    }

    async function buildTenantAIContext(companyId, options = {}) {
        const numericCompanyId = Number(companyId);
        if (!Number.isInteger(numericCompanyId) || numericCompanyId <= 0) {
            throw new Error('A valid companyId is required');
        }

        const [companies] = await pool.query('SELECT * FROM Companies WHERE ID = ? LIMIT 1', [numericCompanyId]);
        if (!companies.length) throw new Error('Company not found');
        const company = normalizeStoredRow(companies[0]);
        const sourceRefreshTimeoutMs = Math.max(
            10 * 1000,
            Number(options.refreshTimeoutMs ?? process.env.STACKCTRL_SOURCE_REFRESH_TIMEOUT_MS) || 180 * 1000
        );
        const capabilities = await loadClientCapabilities({
            pool,
            companyId: numericCompanyId,
            company,
            accessType: options.accessType || null,
            persistDefaults: options.persistCapabilities !== false
        });
        const rawSources = [];
        for (const capability of capabilities) {
            const adapter = SOURCE_ADAPTERS[capability.sourceKey];
            if (!adapter) continue;
            rawSources.push(await adapter({
                pool,
                companyId: numericCompanyId,
                capability,
                refresh: Boolean(options.refresh),
                refreshSource,
                refreshTimeoutMs: sourceRefreshTimeoutMs,
                refreshContext: {
                    ...(options.collectorContext || {}),
                    signal: options.signal || null,
                    sourceKey: capability.sourceKey
                },
                logger
            }));
        }
        // Dashboard context builders add the calculations and evidence lists used by StackCTRL cards.
        const sources = buildDashboardIntelligenceContexts(rawSources);

        const identityTenantEvidence = sources
            .find(source => source.sourceKey === 'identity')
            ?.evidence.find(item => item?.evidenceType === 'tenant')?.data;
        const tenantKey = options.tenantKey || identityTenantEvidence?.TenantID ||
            company.TenantKey || company.tenantKey || `company-${numericCompanyId}`;
        const periodStart = toDateOrNull(options.periodStart);
        const periodEnd = toDateOrNull(options.periodEnd);
        const expectedSources = sources.filter(source => source.isExpected);
        const availableSources = expectedSources.filter(source => ['available', 'stale'].includes(source.status));
        const staleSources = expectedSources.filter(source => source.status === 'stale');
        const unavailableSources = expectedSources.filter(source => !['available', 'stale'].includes(source.status));
        const dataCompletenessScore = expectedSources.length
            ? Number(((availableSources.length / expectedSources.length) * 100).toFixed(2))
            : 100;
        const dataCompleteness = {
            score: dataCompletenessScore,
            expectedSources: expectedSources.length,
            availableSources: availableSources.length,
            staleSources: staleSources.length,
            unavailableSources: unavailableSources.length,
            notExpectedSources: sources.filter(source => source.status === 'not_expected').length
        };
        const sourceMetrics = Object.fromEntries(sources.map(source => [source.sourceKey, source.metrics]));
        // StackCTRL calculates risk before Azure so the frozen snapshot remains the source of truth.
        const riskEngine = buildRiskEngine({ sources, dataCompleteness });
        const metrics = {
            ...sourceMetrics,
            stackctrl_risk: {
                overallRiskScore: riskEngine.overallRiskScore,
                overallRiskLevel: riskEngine.overallRiskLevel,
                securityMaturityScore: riskEngine.securityMaturityScore,
                securityMaturityLevel: riskEngine.securityMaturityLevel,
                domainRiskScores: riskEngine.domainRiskScores
            },
            executive_kpis: riskEngine.executiveKPIs
        };
        const evidence = sources.flatMap(source => source.evidence.map(item => ({
            sourceKey: source.sourceKey,
            displayName: source.displayName,
            data: item
        })));
        const warnings = [...new Set(sources.flatMap(source => source.warnings || []))];
        const sourceSummaries = sources.map(source => ({
            sourceKey: source.sourceKey,
            displayName: source.displayName,
            status: source.status,
            isExpected: source.isExpected,
            freshness: source.freshness,
            credentialSource: source.credentialSource || null,  // NEW: Track which credentials used
            credentialPath: source.credentialPath || null,  // NEW: Show credential path for admin visibility
            refreshFailed: source.refreshFailed || false,
            refreshErrorMessage: source.refreshErrorMessage || null,
            metrics: source.metrics,
            dashboardMetrics: source.dashboardMetrics,
            calculatedIndicators: source.calculatedIndicators,
            evidence: source.evidence,
            evidenceCount: source.evidence.length,
            chartsData: source.chartsData,
            warnings: source.warnings,
            sourceReferences: source.sourceReferences,
            sourceLineage: source.sourceLineage,
            rawReference: source.rawReference,
            errorMessage: source.errorMessage
        }));
        let previousOutputs = [];
        try {
            const [rows] = await pool.query(
                `SELECT ID, SnapshotID, OutputType, Title, ExecutiveSummary, ContentJson,
                        ConfidenceScore, Status, CreatedAt
                 FROM StackCTRLTenantAIOutputs
                 WHERE CompanyID = ? AND Status = 'completed'
                 ORDER BY CreatedAt DESC LIMIT 14`,
                [numericCompanyId]
            );
            previousOutputs = rows.map(normalizeStoredRow);
        } catch (error) {
            if (!isMissingTableError(error)) throw error;
        }

        const context = {
            tenant: {
                companyId: numericCompanyId,
                tenantKey,
                company
            },
            period: {
                start: periodStart ? periodStart.toISOString() : null,
                end: periodEnd ? periodEnd.toISOString() : null,
                generatedAt: new Date().toISOString()
            },
            capabilities: {
                profileKey: capabilities[0]?.profileKey || 'standard',
                sources: capabilities.map(capability => ({
                    sourceKey: capability.sourceKey,
                    isExpected: capability.isExpected,
                    isEnabled: capability.isEnabled,
                    refreshMode: capability.refreshMode
                }))
            },
            sources: sourceSummaries,
            metrics,
            evidence,
            warnings,
            dataCompleteness,
            riskEngine,
            executiveKPIs: riskEngine.executiveKPIs,
            previousIntelligence: previousOutputs,
            aiInstructions: {
                useOnlyStackCTRLData: true,
                stackCTRLCalculatedEvidenceIsPrimary: true,
                externalKnowledgeForInterpretationOnly: true,
                doNotInventFacts: true,
                markMissingDataClearly: true
            },
            intelligenceSchemaVersion: 3
        };

        const sourceFreshness = Object.fromEntries(sources.map(source => [source.sourceKey, {
            status: source.status,
            lastUpdated: source.freshness.lastUpdated,
            ageMinutes: source.freshness.ageMinutes
        }]));

        return {
            companyId: numericCompanyId,
            tenantKey,
            periodStart,
            periodEnd,
            sourceFreshness,
            metrics,
            evidence,
            sources,
            capabilities,
            dataCompleteness,
            riskEngine,
            context,
            dataCompletenessScore
        };
    }

    async function createSnapshot({ companyId, options = {}, user = {} }) {
        const built = await buildTenantAIContext(companyId, options);
        const snapshotType = String(options.snapshotType || 'ai_context').slice(0, 80);
        return persistBuiltSnapshot({ built, snapshotType, user });
    }

    async function createSnapshotFromBuiltContext({ built, snapshotType = 'scheduled', user = {} }) {
        if (!built?.companyId || !built?.context || !Array.isArray(built.sources)) {
            throw new Error('A valid collected tenant context is required');
        }
        return persistBuiltSnapshot({
            built,
            snapshotType: String(snapshotType).slice(0, 80),
            user
        });
    }

    async function persistBuiltSnapshot({ built, snapshotType, user }) {
        const actor = user && typeof user === 'object' ? user : {};
        const connection = await pool.getConnection();
        let snapshotId;
        try {
            await connection.beginTransaction();
            const [result] = await connection.query(
                `INSERT INTO StackCTRLTenantEvidenceSnapshots
                 (CompanyID, TenantKey, PeriodStart, PeriodEnd, SnapshotType,
                  SourceFreshnessJson, MetricsJson, EvidenceJson, ContextJson,
                  DataCompletenessScore, CreatedByUserID, CreatedByEmail)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    built.companyId,
                    built.tenantKey,
                    built.periodStart,
                    built.periodEnd,
                    snapshotType,
                    JSON.stringify(built.sourceFreshness),
                    JSON.stringify(built.metrics),
                    JSON.stringify(built.evidence),
                    JSON.stringify(built.context),
                    built.dataCompletenessScore,
                    actor.id || actor.userId || null,
                    actor.email || null
                ]
            );
            snapshotId = result.insertId;

            // We store one status row per adapter so every snapshot can be audited source by source.
            for (const source of built.sources) {
                const [statusResult] = await connection.query(
                    `INSERT INTO StackCTRLIntelligenceSourceStatus
                     (CompanyID, SnapshotID, SourceKey, DisplayName, Status, IsExpected,
                      LastUpdated, AgeMinutes, EvidenceCount, MetricsJson, WarningsJson,
                      RawReferenceJson, ErrorMessage)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        built.companyId,
                        snapshotId,
                        source.sourceKey,
                        source.displayName,
                        source.status,
                        source.isExpected ? 1 : 0,
                        toDateOrNull(source.freshness.lastUpdated),
                        source.freshness.ageMinutes,
                        source.evidence.length,
                        JSON.stringify(source.metrics || {}),
                        JSON.stringify(source.warnings || []),
                        JSON.stringify(source.rawReference || {}),
                        source.errorMessage || null
                    ]
                );

                for (const metric of flattenMetrics(source.metrics || {})) {
                    await connection.query(
                        `INSERT INTO StackCTRLIntelligenceMetrics
                         (CompanyID, SnapshotID, SourceStatusID, SourceKey, MetricName,
                          MetricLabel, MetricType, NumericValue, TextValue, BooleanValue,
                          JsonValue, PeriodStart, PeriodEnd)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [
                            built.companyId,
                            snapshotId,
                            statusResult.insertId,
                            source.sourceKey,
                            String(metric.name || 'value').slice(0, 150),
                            String(metric.name || 'value').slice(0, 180),
                            metric.type,
                            metric.numericValue ?? null,
                            metric.textValue ?? null,
                            metric.booleanValue == null ? null : (metric.booleanValue ? 1 : 0),
                            metric.jsonValue == null ? null : JSON.stringify(metric.jsonValue),
                            built.periodStart,
                            built.periodEnd
                        ]
                    );
                }
            }
            await connection.commit();
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }

        return {
            snapshotId,
            companyId: built.companyId,
            tenantKey: built.tenantKey,
            snapshotType,
            dataCompletenessScore: built.dataCompletenessScore,
            dataCompleteness: built.dataCompleteness,
            riskEngine: built.riskEngine,
            sourceStatuses: built.sources.map(source => ({
                sourceKey: source.sourceKey,
                displayName: source.displayName,
                status: source.status,
                isExpected: source.isExpected,
                freshness: source.freshness,
                warnings: source.warnings
            })),
            warnings: built.context.warnings,
            sourceFreshness: built.sourceFreshness
        };
    }

    async function bootstrap({ companyId, accessType = null, user = {} }) {
        return createSnapshot({
            companyId,
            options: {
                snapshotType: 'bootstrap',
                refresh: true,
                accessType
            },
            user
        });
    }

    async function bootstrapAvailableTenants() {
        const [companies] = await pool.query('SELECT * FROM Companies ORDER BY ID');
        const results = [];
        for (const company of companies) {
            try {
                const [recent] = await pool.query(
                    `SELECT ID FROM StackCTRLTenantEvidenceSnapshots
                     WHERE CompanyID = ?
                       AND SnapshotType = 'deployment_bootstrap'
                       AND CreatedAt >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
                     ORDER BY CreatedAt DESC LIMIT 1`,
                    [company.ID]
                );
                if (recent.length) {
                    results.push({ companyId: company.ID, snapshotId: recent[0].ID, status: 'already_stored' });
                    continue;
                }
                const snapshot = await createSnapshot({
                    companyId: company.ID,
                    options: {
                        snapshotType: 'deployment_bootstrap',
                        refresh: false,
                        persistCapabilities: true
                    }
                });
                results.push({ companyId: company.ID, snapshotId: snapshot.snapshotId, status: 'stored' });
            } catch (error) {
                logger.warn(`[StackCTRL Intelligence] Deployment bootstrap skipped company ${company.ID}:`, error.message);
                results.push({ companyId: company.ID, status: 'failed', message: error.message });
            }
        }
        return results;
    }

    function validateOutputTypes(outputTypes) {
        if (!Array.isArray(outputTypes) || !outputTypes.length) {
            throw new Error('At least one outputType is required');
        }
        const unique = [...new Set(outputTypes.map(value => String(value).trim()))];
        const invalid = unique.filter(value => !ALLOWED_OUTPUT_TYPES.has(value));
        if (invalid.length) throw new Error(`Unsupported outputTypes: ${invalid.join(', ')}`);
        return unique;
    }

    function buildRequiredOutputContract(outputTypes) {
        return `Analyse the supplied StackCTRL snapshot and return one JSON object.

Requested output types: ${outputTypes.join(', ')}

StackCTRL-calculated tenant evidence is the primary source of truth. Use external/grounding knowledge only to interpret risk, best practices, and recommendations.

Write decision-ready enterprise intelligence. Explain business impact, cite the relevant StackCTRL source/evidence in each material risk, distinguish evidence from interpretation, and do not merely repeat metrics.
Treat Operations and Applications as first-class reporting domains whenever their source evidence is expected and available.
The StackCTRL riskEngine values are authoritative. Explain them, but never replace or recalculate the overall risk score, risk level, domain scores, maturity score, or executive KPIs.
Compare the current snapshot against every available historical period in historicalComparisons: previous, 24 hours, 7 days, 30 days, and 90 days. State clearly when a period is unavailable.
For weekly, monthly, and yearly reports, use periodRollups to explain movement across the completed lower-level reporting periods. Do not treat a missing rollup as zero activity.

Return this exact top-level structure:
{
  "executive_summary": {},
  "overall_risk_score": 0,
  "risk_level": "low | moderate | high | critical",
  "governance_assessment": {},
  "compliance_review": {},
  "risk_register": [],
  "recommendations": [],
  "trend_analysis": [],
  "board_report": {},
  "powerbi_summary": {
    "risk_score": 0,
    "risk_level": "low | moderate | high | critical",
    "maturity_level": "initial | developing | defined | managed | optimised",
    "security_maturity_score": 0,
    "top_risk_domain": "",
    "top_recommendation": "",
    "mfa_coverage": null,
    "device_compliance": null,
    "high_severity_alerts": null,
    "cloudflare_status": "available | stale | missing | not_configured | not_expected | error",
    "data_completeness_score": null,
    "security_health": null,
    "governance_health": null,
    "compliance_health": null,
    "identity_health": null,
    "device_health": null,
    "email_health": null,
    "backup_health": null,
    "operations_health": null,
    "applications_health": null,
    "domain_risk_scores": {}
  }
}

Risk fields: domain, title, description, severity, likelihood, impact, businessImpact, evidenceSummary, recommendation.
Recommendation fields: domain, title, detail, priority, businessReason, suggestedOwner, suggestedDueDate.
Trend fields: metricName, domain, currentValue, previousValue, changePercent, direction, comparisonPeriod, explanation.
Use comparisonPeriod values previous, 24_hours, 7_days, 30_days, or 90_days when the trend is tied to an available historical baseline. Otherwise return null.

Overall risk score must be a number from 0 to 100 where a higher score means greater risk. Keep Power BI field names and primitive value types exactly as shown.
Do not add tenant claims that are not supported by the snapshot. Use empty objects, arrays, or null for unrequested output types.`;
    }

    function buildAnalysisPrompt(context, outputTypes) {
        return `${buildRequiredOutputContract(outputTypes)}

STACKCTRL SNAPSHOT:
${JSON.stringify(context)}`;
    }

    async function loadAnalysisPrompt(companyId, context, outputTypes) {
        const [rows] = await pool.query(
            `SELECT * FROM StackCTRLIntelligencePrompts
             WHERE PromptKey = 'tenant_analysis'
               AND IsActive = 1
               AND (CompanyID = ? OR CompanyID IS NULL)
             ORDER BY (CompanyID = ?) DESC, UpdatedAt DESC, ID DESC
             LIMIT 1`,
            [companyId, companyId]
        );
        const prompt = rows[0] ? normalizeStoredRow(rows[0]) : null;
        const tenantSystemPrompt = String(prompt?.SystemPrompt || '').trim();
        const systemPrompt = tenantSystemPrompt
            ? `${SYSTEM_PROMPT}\n\nTenant-specific analysis instructions:\n${tenantSystemPrompt}`
            : SYSTEM_PROMPT;
        if (!prompt?.UserPromptTemplate) {
            return {
                systemPrompt,
                userPrompt: buildAnalysisPrompt(context, outputTypes),
                promptVersion: prompt?.PromptVersion || PROMPT_VERSION
            };
        }

        const userPromptTemplate = String(prompt.UserPromptTemplate);
        const userPrompt = userPromptTemplate
            .split('{{outputTypes}}').join(outputTypes.join(', '))
            .split('{{contextJson}}').join(JSON.stringify(context));
        const snapshotAppendix = userPromptTemplate.includes('{{contextJson}}')
            ? ''
            : `\n\nSTACKCTRL SNAPSHOT:\n${JSON.stringify(context)}`;
        return {
            systemPrompt,
            // Database prompts may add tenant guidance, but the enterprise output contract is always enforced.
            userPrompt: `${userPrompt}${snapshotAppendix}\n\nMANDATORY STACKCTRL OUTPUT CONTRACT:\n${buildRequiredOutputContract(outputTypes)}`,
            promptVersion: prompt.PromptVersion || PROMPT_VERSION
        };
    }

    async function analyseSnapshot({
        snapshotId,
        companyId,
        outputTypes,
        user = {},
        historicalContext = null,
        analysisMode = 'compact',
        compactContext = null,
        periodType = 'snapshot'
    }) {
        const requestedTypes = validateOutputTypes(outputTypes);
        const [snapshots] = await pool.query(
            `SELECT * FROM StackCTRLTenantEvidenceSnapshots
             WHERE ID = ? AND CompanyID = ?
             LIMIT 1`,
            [snapshotId, companyId]
        );
        if (!snapshots.length) throw new Error('Snapshot not found');

        const snapshot = normalizeStoredRow(snapshots[0]);
        const [runResult] = await pool.query(
            `INSERT INTO StackCTRLIntelligenceRuns
             (CompanyID, SnapshotID, Status, RequestedOutputTypes, CreatedByUserID, CreatedByEmail)
             VALUES (?, ?, 'pending', ?, ?, ?)`,
            [companyId, snapshotId, JSON.stringify(requestedTypes), user.id || user.userId || null, user.email || null]
        );
        const runId = runResult.insertId;
        let completionMetadata = {};

        try {
            const mode = String(analysisMode || 'compact').toLowerCase();
            if (!['compact', 'full'].includes(mode)) throw new Error('analysisMode must be compact or full');
            let compactBuild = null;
            let analysisContext;
            if (mode === 'full') {
                analysisContext = historicalContext || snapshot.ContextJson;
            } else if (compactContext?.compactContextJson) {
                compactBuild = compactContext;
                analysisContext = compactContext.compactContextJson;
            } else if (compactContext?.contextType === 'stackctrl_compact_intelligence') {
                analysisContext = compactContext;
            } else {
                compactBuild = await buildCompactContext({
                    companyId,
                    snapshotId,
                    periodType,
                    historicalContext
                });
                analysisContext = compactBuild.compactContextJson;
            }
            const prompt = await loadAnalysisPrompt(companyId, analysisContext, requestedTypes);
            // Azure only receives the frozen StackCTRL snapshot. Vendor refreshes happen before this point.
            const completion = await azureOpenAI.createJsonCompletion({
                temperature: 0.1,
                maxTokens: 5000,
                messages: [
                    { role: 'system', content: prompt.systemPrompt },
                    { role: 'user', content: prompt.userPrompt }
                ],
                onStatusChange: status => updateIntelligenceRun(pool, runId, status.status, status)
            });
            completionMetadata = {
                model: completion.model || completion.deployment,
                deployment: completion.deployment,
                requestSizeBytes: completion.requestSizeBytes,
                responseSizeBytes: completion.responseSizeBytes,
                tokenUsage: completion.usage,
                retryCount: completion.retryCount
            };
            const analysis = completion.data && typeof completion.data === 'object' ? completion.data : {};
            const currentStackCTRLContext = stackCTRLContextForAnalysis(analysisContext);
            analysis.overall_risk_score = toNullableNumber(
                currentStackCTRLContext.riskEngine?.overallRiskScore ?? analysis.overall_risk_score ?? analysis.powerbi_summary?.risk_score
            );
            analysis.risk_level = toNullableText(
                currentStackCTRLContext.riskEngine?.overallRiskLevel ?? analysis.risk_level ?? analysis.powerbi_summary?.risk_level
            );
            analysis.powerbi_summary = normalizePowerBISummary(analysis.powerbi_summary, analysis, currentStackCTRLContext);
            const connection = await pool.getConnection();
            const outputIds = {};

            try {
                await connection.beginTransaction();

                for (const outputType of requestedTypes) {
                    const arrayOutput = outputType.endsWith('_register') || outputType.endsWith('_analysis') || outputType === 'recommendations';
                    const scalarOutput = outputType === 'overall_risk_score' || outputType === 'risk_level';
                    const content = analysis[outputType] ?? (arrayOutput ? [] : scalarOutput ? null : {});
                    const summary = typeof content?.executiveSummary === 'string'
                        ? content.executiveSummary
                        : typeof content?.summary === 'string'
                            ? content.summary
                            : outputType === 'executive_summary' && typeof content === 'string'
                                ? content
                                : null;
                    const confidence = toNullableNumber(content?.confidenceScore ?? analysis.confidenceScore);
                    const [outputResult] = await connection.query(
                        `INSERT INTO StackCTRLTenantAIOutputs
                         (CompanyID, SnapshotID, OutputType, Title, ExecutiveSummary, ContentJson,
                          ModelName, AzureDeployment, PromptVersion, ConfidenceScore, Status,
                          CreatedByUserID, CreatedByEmail)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)`,
                        [
                            companyId,
                            snapshotId,
                            outputType,
                            OUTPUT_TITLES[outputType],
                            summary,
                            JSON.stringify(content),
                            completion.model || completion.deployment,
                            completion.deployment,
                            prompt.promptVersion,
                            confidence,
                            user.id || user.userId || null,
                            user.email || null
                        ]
                    );
                    outputIds[outputType] = outputResult.insertId;
                }

                if (requestedTypes.includes('risk_register')) {
                    for (const risk of Array.isArray(analysis.risk_register) ? analysis.risk_register : []) {
                        await connection.query(
                            `INSERT INTO StackCTRLTenantRiskRegister
                             (CompanyID, SnapshotID, AIOutputID, Domain, RiskTitle, RiskDescription,
                              Severity, Likelihood, Impact, BusinessImpact, EvidenceSummary, Recommendation)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [
                                companyId, snapshotId, outputIds.risk_register,
                                String(risk.domain || 'General').slice(0, 120),
                                String(risk.title || 'Untitled risk').slice(0, 255),
                                risk.description || null,
                                String(risk.severity || 'Unknown').slice(0, 50),
                                risk.likelihood || null,
                                risk.impact || null,
                                risk.businessImpact || null,
                                risk.evidenceSummary || null,
                                risk.recommendation || null
                            ]
                        );
                    }
                }

                if (requestedTypes.includes('recommendations')) {
                    for (const recommendation of Array.isArray(analysis.recommendations) ? analysis.recommendations : []) {
                        await connection.query(
                            `INSERT INTO StackCTRLTenantRecommendations
                             (CompanyID, SnapshotID, AIOutputID, Domain, RecommendationTitle,
                              RecommendationDetail, Priority, BusinessReason, SuggestedOwner, SuggestedDueDate)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [
                                companyId, snapshotId, outputIds.recommendations,
                                String(recommendation.domain || 'General').slice(0, 120),
                                String(recommendation.title || 'Untitled recommendation').slice(0, 255),
                                recommendation.detail || null,
                                String(recommendation.priority || 'Unspecified').slice(0, 50),
                                recommendation.businessReason || null,
                                recommendation.suggestedOwner || null,
                                toNullableDate(recommendation.suggestedDueDate)
                            ]
                        );
                    }
                }

                if (requestedTypes.includes('trend_analysis')) {
                    for (const trend of Array.isArray(analysis.trend_analysis) ? analysis.trend_analysis : []) {
                        await connection.query(
                        `INSERT INTO StackCTRLTenantTrendAnalysis
                             (CompanyID, SnapshotID, AIOutputID, MetricName, Domain, CurrentValue,
                              PreviousValue, ChangePercent, Direction, ComparisonPeriod, Explanation)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [
                                companyId, snapshotId, outputIds.trend_analysis,
                                String(trend.metricName || 'Unspecified metric').slice(0, 150),
                                trend.domain || null,
                                toNullableNumber(trend.currentValue),
                                toNullableNumber(trend.previousValue),
                                toNullableNumber(trend.changePercent),
                                trend.direction || null,
                                toNullableText(trend.comparisonPeriod ?? trend.comparison_period),
                                trend.explanation || null
                            ]
                        );
                    }
                }

                await updateIntelligenceRun(connection, runId, 'completed', completionMetadata);
                await connection.commit();
            } catch (error) {
                await connection.rollback();
                throw error;
            } finally {
                connection.release();
            }

            return {
                runId,
                snapshotId: Number(snapshotId),
                companyId: Number(companyId),
                analysisMode: mode,
                compactContextId: compactBuild?.compactContextId || null,
                outputIds,
                runStatus: 'completed',
                retryCount: completion.retryCount || 0,
                requestSizeBytes: completion.requestSizeBytes,
                responseSizeBytes: completion.responseSizeBytes,
                tokenUsage: completion.usage || null,
                payloadComparison: {
                    fullContextSizeBytes: compactBuild?.fullContextSizeBytes || sizeBytes(snapshot.ContextJson || {}),
                    compactContextSizeBytes: compactBuild?.compactContextSizeBytes || null,
                    reductionPercentage: compactBuild?.reductionPercentage ?? null,
                    evidenceIncludedCount: compactBuild?.evidenceIncludedCount ?? null,
                    evidenceOmittedCount: compactBuild?.evidenceOmittedCount ?? null
                },
                preview: {
                    executiveSummary: analysis.executive_summary?.summary || analysis.executive_summary?.executiveSummary || null,
                    overallRiskScore: toNullableNumber(analysis.overall_risk_score ?? analysis.powerbi_summary?.risk_score),
                    riskLevel: analysis.risk_level || analysis.powerbi_summary?.risk_level || null,
                    risks: Array.isArray(analysis.risk_register) ? analysis.risk_register.length : 0,
                    recommendations: Array.isArray(analysis.recommendations) ? analysis.recommendations.length : 0,
                    trends: Array.isArray(analysis.trend_analysis) ? analysis.trend_analysis.length : 0,
                    powerbiSummary: analysis.powerbi_summary || null
                }
            };
        } catch (error) {
            await updateIntelligenceRun(pool, runId, 'failed', {
                ...completionMetadata,
                ...(error.azureMetadata || {}),
                errorMessage: error.message || 'Analysis failed'
            }).catch(updateError => logger.error('[StackCTRL Intelligence] Failed to update run status:', updateError.message));
            throw error;
        }
    }

    async function runPeriodIntelligence({
        companyId,
        periodType,
        snapshotId = null,
        referenceDate = new Date(),
        historicalContext = null,
        outputTypes = null,
        user = {}
    }) {
        const window = getPeriodWindow(periodType, referenceDate);
        const snapshot = await loadSnapshot(companyId, snapshotId);
        const compact = await buildCompactContext({
            companyId,
            snapshotId: snapshot.ID,
            periodType: window.periodType,
            periodStart: window.periodStart,
            periodEnd: window.periodEnd,
            historicalContext
        });
        const requestedTypes = Array.isArray(outputTypes) && outputTypes.length
            ? validateOutputTypes(outputTypes)
            : PERIOD_OUTPUT_TYPES[window.periodType];
        const [periodResult] = await pool.query(
            `INSERT INTO StackCTRLIntelligencePeriods
             (CompanyID, SnapshotID, CompactContextID, PeriodType, PeriodStart, PeriodEnd, Status)
             VALUES (?, ?, ?, ?, ?, ?, 'processing')
             ON DUPLICATE KEY UPDATE
                ID = LAST_INSERT_ID(ID),
                SnapshotID = VALUES(SnapshotID),
                CompactContextID = VALUES(CompactContextID),
                Status = 'processing'`,
            [
                Number(companyId),
                snapshot.ID,
                compact.compactContextId,
                window.periodType,
                window.periodStart,
                window.periodEnd
            ]
        );
        const periodId = Number(periodResult.insertId);

        try {
            const analysis = await analyseSnapshot({
                snapshotId: snapshot.ID,
                companyId: Number(companyId),
                outputTypes: requestedTypes,
                user,
                historicalContext,
                compactContext: compact,
                analysisMode: 'compact',
                periodType: window.periodType
            });
            const riskOutputId = analysis.outputIds.risk_register || null;
            const recommendationOutputId = analysis.outputIds.recommendations || null;
            const [[riskRows], [recommendationRows]] = await Promise.all([
                riskOutputId
                    ? pool.query(
                        `SELECT RiskTitle FROM StackCTRLTenantRiskRegister
                         WHERE AIOutputID = ? ORDER BY ID ASC LIMIT 1`,
                        [riskOutputId]
                    )
                    : Promise.resolve([[]]),
                recommendationOutputId
                    ? pool.query(
                        `SELECT RecommendationTitle FROM StackCTRLTenantRecommendations
                         WHERE AIOutputID = ? ORDER BY ID ASC LIMIT 1`,
                        [recommendationOutputId]
                    )
                    : Promise.resolve([[]])
            ]);
            const risk = compact.riskScores || {};
            const health = compact.healthKpis || {};
            const domainRisk = risk.domainRiskScores || {};
            const cloudflareRisk = toNullableNumber(domainRisk.cloudflare ?? domainRisk.network ?? domainRisk.network_security);
            const azureOutputId = analysis.outputIds.powerbi_summary || analysis.outputIds.executive_summary || Object.values(analysis.outputIds)[0] || null;
            await pool.query(
                `UPDATE StackCTRLIntelligencePeriods
                 SET Status = 'completed', RiskScore = ?, RiskLevel = ?, MaturityScore = ?,
                     IdentityHealth = ?, DeviceHealth = ?, EmailHealth = ?, CloudflareHealth = ?,
                     BackupHealth = ?, GovernanceHealth = ?, ComplianceHealth = ?,
                     OperationsHealth = ?, ApplicationsHealth = ?,
                     ExecutiveSummary = ?, TopRisk = ?, TopRecommendation = ?, AzureOutputID = ?
                 WHERE ID = ?`,
                [
                    toNullableNumber(risk.overallRiskScore),
                    toNullableText(risk.overallRiskLevel),
                    toNullableNumber(risk.securityMaturityScore),
                    toNullableNumber(health.identityHealth),
                    toNullableNumber(health.deviceHealth),
                    toNullableNumber(health.emailHealth),
                    cloudflareRisk == null ? null : Number((100 - cloudflareRisk).toFixed(2)),
                    toNullableNumber(health.backupHealth),
                    toNullableNumber(health.governanceHealth),
                    toNullableNumber(health.complianceHealth),
                    toNullableNumber(health.operationsHealth),
                    toNullableNumber(health.applicationsHealth),
                    analysis.preview.executiveSummary,
                    riskRows[0]?.RiskTitle || null,
                    recommendationRows[0]?.RecommendationTitle || null,
                    azureOutputId,
                    periodId
                ]
            );
            const [rows] = await pool.query('SELECT * FROM StackCTRLIntelligencePeriods WHERE ID = ? LIMIT 1', [periodId]);
            return {
                period: normalizeStoredRow(rows[0]),
                compactContext: {
                    id: compact.compactContextId,
                    fullContextSizeBytes: compact.fullContextSizeBytes,
                    compactContextSizeBytes: compact.compactContextSizeBytes,
                    reductionPercentage: compact.reductionPercentage,
                    evidenceIncludedCount: compact.evidenceIncludedCount,
                    evidenceOmittedCount: compact.evidenceOmittedCount,
                    historicalAvailability: compact.historicalAvailability
                },
                analysis
            };
        } catch (error) {
            await pool.query(
                `UPDATE StackCTRLIntelligencePeriods SET Status = 'failed' WHERE ID = ?`,
                [periodId]
            ).catch(updateError => logger.error('[StackCTRL Intelligence] Failed to update period status:', updateError.message));
            throw error;
        }
    }

    async function getIntelligencePeriods(companyId, limit = 100) {
        const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
        const [rows] = await pool.query(
            `SELECT * FROM StackCTRLIntelligencePeriods
             WHERE CompanyID = ? ORDER BY PeriodStart DESC, ID DESC LIMIT ?`,
            [Number(companyId), safeLimit]
        );
        return rows.map(normalizeStoredRow);
    }

    async function getLatest({ companyId, outputType = null }) {
        const params = [companyId];
        let filter = '';
        if (outputType) {
            if (!ALLOWED_OUTPUT_TYPES.has(outputType)) throw new Error('Unsupported outputType');
            filter = ' AND OutputType = ?';
            params.push(outputType);
        }

        const [outputs] = await pool.query(
            `SELECT * FROM StackCTRLTenantAIOutputs
             WHERE CompanyID = ?${filter}
             ORDER BY CreatedAt DESC
             LIMIT 50`,
            params
        );
        const normalizedOutputs = outputs.map(normalizeStoredRow);
        const outputIds = normalizedOutputs.map(item => item.ID);
        if (!outputIds.length) return { outputs: [], risks: [], recommendations: [], trends: [] };

        const [risks, recommendations, trends] = await Promise.all([
            pool.query('SELECT * FROM StackCTRLTenantRiskRegister WHERE CompanyID = ? AND AIOutputID IN (?) ORDER BY CreatedAt DESC', [companyId, outputIds]),
            pool.query('SELECT * FROM StackCTRLTenantRecommendations WHERE CompanyID = ? AND AIOutputID IN (?) ORDER BY CreatedAt DESC', [companyId, outputIds]),
            pool.query('SELECT * FROM StackCTRLTenantTrendAnalysis WHERE CompanyID = ? AND AIOutputID IN (?) ORDER BY CreatedAt DESC', [companyId, outputIds])
        ]);

        return {
            outputs: normalizedOutputs,
            risks: risks[0].map(normalizeStoredRow),
            recommendations: recommendations[0].map(normalizeStoredRow),
            trends: trends[0].map(normalizeStoredRow)
        };
    }

    async function getPowerBIData(companyId) {
        const [outputs, risks, recommendations, trends, snapshotIntelligence, periods] = await Promise.all([
            pool.query(
                `SELECT ID, CompanyID, SnapshotID, OutputType, Title, ExecutiveSummary, ContentJson,
                        ModelName, AzureDeployment, PromptVersion, ConfidenceScore, Status, CreatedAt
                 FROM StackCTRLTenantAIOutputs WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 1000`,
                [companyId]
            ),
            pool.query('SELECT * FROM StackCTRLTenantRiskRegister WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 5000', [companyId]),
            pool.query('SELECT * FROM StackCTRLTenantRecommendations WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 5000', [companyId]),
            pool.query('SELECT * FROM StackCTRLTenantTrendAnalysis WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 5000', [companyId]),
            pool.query(
                `SELECT ID AS SnapshotID, CompanyID, SnapshotType, DataCompletenessScore, CreatedAt,
                        JSON_EXTRACT(MetricsJson, '$.stackctrl_risk') AS RiskJson,
                        JSON_EXTRACT(MetricsJson, '$.executive_kpis') AS ExecutiveKPIsJson
                 FROM StackCTRLTenantEvidenceSnapshots
                 WHERE CompanyID = ?
                 ORDER BY CreatedAt DESC LIMIT 1000`,
                [companyId]
            ),
            pool.query(
                `SELECT * FROM StackCTRLIntelligencePeriods
                 WHERE CompanyID = ? ORDER BY PeriodStart DESC, ID DESC LIMIT 1000`,
                [companyId]
            )
        ]);

        const normalizedOutputs = outputs[0].map(normalizeStoredRow);
        return {
            outputs: normalizedOutputs,
            powerbiSummaries: normalizedOutputs
                .filter(output => output.OutputType === 'powerbi_summary')
                .map(output => ({
                    companyId: output.CompanyID,
                    snapshotId: output.SnapshotID,
                    createdAt: output.CreatedAt,
                    ...(output.ContentJson || {})
                })),
            snapshotIntelligence: snapshotIntelligence[0].map(row => {
                const normalized = normalizeStoredRow(row);
                return {
                    snapshotId: normalized.SnapshotID,
                    companyId: normalized.CompanyID,
                    snapshotType: normalized.SnapshotType,
                    createdAt: normalized.CreatedAt,
                    dataCompletenessScore: toNullableNumber(normalized.DataCompletenessScore),
                    risk: normalized.RiskJson || {},
                    executiveKPIs: normalized.ExecutiveKPIsJson || {}
                };
            }),
            risks: risks[0].map(normalizeStoredRow),
            recommendations: recommendations[0].map(normalizeStoredRow),
            trends: trends[0].map(normalizeStoredRow),
            intelligencePeriods: periods[0].map(normalizeStoredRow)
        };
    }

    return {
        buildTenantAIContext,
        buildCompactContext,
        getCompactContext,
        createSnapshot,
        createSnapshotFromBuiltContext,
        bootstrap,
        bootstrapAvailableTenants,
        analyseSnapshot,
        runPeriodIntelligence,
        getIntelligencePeriods,
        getLatest,
        getPowerBIData,
        validateOutputTypes
    };
}

module.exports = {
    ALLOWED_OUTPUT_TYPES,
    PERIOD_OUTPUT_TYPES,
    SYSTEM_PROMPT,
    createStackCTRLIntelligenceService
};
