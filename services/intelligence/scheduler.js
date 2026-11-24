const crypto = require('crypto');
const { DateTime } = require('luxon');
const { buildHistoricalIntelligence } = require('./historical-engine');

const TIME_ZONE = 'Africa/Johannesburg';
const BUSINESS_START_MINUTE = 8 * 60;
const BUSINESS_END_MINUTE = 18 * 60;
const ANALYSIS_HOURS = new Set([8, 12, 16, 18]);
const DEFAULT_OUTPUT_TYPES = [
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
];

const DEFAULT_SCHEDULES = [
    {
        scheduleKey: 'collection_15m',
        scheduleType: 'collection',
        cron: '*/15 8-18 * * 1-5',
        intervalMinutes: 15,
        analysisHours: null,
        outputTypes: null
    },
    {
        scheduleKey: 'snapshot_hourly',
        scheduleType: 'snapshot',
        cron: '0 8-18 * * 1-5',
        intervalMinutes: 60,
        analysisHours: null,
        outputTypes: null
    },
    {
        scheduleKey: 'azure_analysis',
        scheduleType: 'analysis',
        cron: '0 8,12,16,18 * * 1-5',
        intervalMinutes: null,
        analysisHours: [8, 12, 16, 18],
        outputTypes: DEFAULT_OUTPUT_TYPES
    }
];

const HISTORICAL_TARGETS = [
    { key: 'previous', minutes: 0, toleranceMinutes: null },
    { key: '24_hours', minutes: 24 * 60, toleranceMinutes: 12 * 60 },
    { key: '7_days', minutes: 7 * 24 * 60, toleranceMinutes: 2 * 24 * 60 },
    { key: '30_days', minutes: 30 * 24 * 60, toleranceMinutes: 7 * 24 * 60 },
    { key: '90_days', minutes: 90 * 24 * 60, toleranceMinutes: 14 * 24 * 60 }
];

function parseJson(value, fallback = null) {
    if (value == null) return fallback;
    if (typeof value === 'object') return value;
    try {
        return JSON.parse(value);
    } catch (_) {
        return fallback;
    }
}

function numberFrom(object, keys) {
    for (const key of keys) {
        const value = object?.[key];
        if (value !== null && value !== undefined && Number.isFinite(Number(value))) return Number(value);
    }
    return null;
}

function flattenNumbers(value, prefix = '', output = {}) {
    if (!value || typeof value !== 'object') return output;
    for (const [key, nested] of Object.entries(value)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (typeof nested === 'number' && Number.isFinite(nested)) output[path] = nested;
        else if (nested && typeof nested === 'object' && !Array.isArray(nested)) flattenNumbers(nested, path, output);
    }
    return output;
}

function compareMetrics(current, baseline) {
    const currentNumbers = flattenNumbers(current || {});
    const baselineNumbers = flattenNumbers(baseline || {});
    const changes = {};
    for (const [name, currentValue] of Object.entries(currentNumbers)) {
        if (!Number.isFinite(baselineNumbers[name])) continue;
        const previousValue = baselineNumbers[name];
        changes[name] = {
            currentValue,
            previousValue,
            change: currentValue - previousValue,
            changePercent: previousValue === 0
                ? null
                : Number((((currentValue - previousValue) / Math.abs(previousValue)) * 100).toFixed(2))
        };
    }
    return changes;
}

function serializeSnapshot(row) {
    if (!row) return null;
    return {
        snapshotId: row.ID,
        companyId: row.CompanyID,
        snapshotType: row.SnapshotType,
        createdAt: row.CreatedAt,
        dataCompletenessScore: Number(row.DataCompletenessScore || 0),
        metrics: parseJson(row.MetricsJson, {}),
        context: parseJson(row.ContextJson, {})
    };
}

function localTime(value = new Date()) {
    return DateTime.fromJSDate(value instanceof Date ? value : new Date(value), { zone: 'utc' }).setZone(TIME_ZONE);
}

function isBusinessTime(local) {
    const weekday = local.weekday >= 1 && local.weekday <= 5;
    const minute = (local.hour * 60) + local.minute;
    return weekday && minute >= BUSINESS_START_MINUTE && minute <= BUSINESS_END_MINUTE;
}

function makeDeduplicationKey(companyId, scheduleKey, bucket) {
    return `${companyId}:${scheduleKey}:${bucket}`;
}

function criticalFingerprint(companyId, signal, local) {
    const bucket = local.toFormat('yyyyLLddHH');
    const raw = `${companyId}:${signal.sourceKey}:${signal.eventType}:${bucket}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
}

function createStackCTRLIntelligenceScheduler({ pool, intelligenceService, logger = console } = {}) {
    if (!pool) throw new Error('StackCTRL Intelligence Scheduler requires a database pool');
    if (!intelligenceService) throw new Error('StackCTRL Intelligence Scheduler requires the intelligence service');
    let historicalComparisonWarningShown = false;
    let missingScheduleTableWarningShown = false;
    let disabledSchedulesWarningShown = false;

    async function ensureTenantSchedules(companyId) {
        try {
            for (const schedule of DEFAULT_SCHEDULES) {
                await pool.query(
                `INSERT INTO StackCTRLIntelligenceSchedules
                 (CompanyID, ScheduleKey, ScheduleType, CronExpression, TimeZone,
                  BusinessDaysJson, BusinessStartTime, BusinessEndTime, IntervalMinutes,
                  AnalysisHoursJson, OutputTypesJson)
                 VALUES (?, ?, ?, ?, ?, ?, '08:00:00', '18:00:00', ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                    ScheduleType = VALUES(ScheduleType),
                    CronExpression = VALUES(CronExpression),
                    TimeZone = VALUES(TimeZone)`,
                [
                    companyId,
                    schedule.scheduleKey,
                    schedule.scheduleType,
                    schedule.cron,
                    TIME_ZONE,
                    JSON.stringify([1, 2, 3, 4, 5]),
                    schedule.intervalMinutes,
                    schedule.analysisHours ? JSON.stringify(schedule.analysisHours) : null,
                    schedule.outputTypes ? JSON.stringify(schedule.outputTypes) : null
                ]
                );
            }
            const [rows] = await pool.query(
                `SELECT * FROM StackCTRLIntelligenceSchedules
                 WHERE CompanyID = ? ORDER BY ID`,
                [companyId]
            );
            return rows;
        } catch (error) {
            if (error?.code !== 'ER_NO_SUCH_TABLE') throw error;
            if (!missingScheduleTableWarningShown) {
                missingScheduleTableWarningShown = true;
                logger.warn('[StackCTRL Intelligence Scheduler] Schedule tables are not available yet. Scheduled automation is paused until ensureDatabaseSchema creates them.');
            }
            return [];
        }
    }

    async function preventDuplicateScheduledRuns(companyId, scheduleKey, timeWindow) {
        const start = timeWindow?.start || new Date(Date.now() - ((timeWindow?.minutes || 15) * 60000));
        const end = timeWindow?.end || new Date();
        const [rows] = await pool.query(
            `SELECT ID, Status, SnapshotID, IntelligenceRunID
             FROM StackCTRLIntelligenceScheduleRuns
             WHERE CompanyID = ? AND ScheduleKey = ?
               AND StartedAt BETWEEN ? AND ?
             ORDER BY StartedAt DESC LIMIT 1`,
            [companyId, scheduleKey, start, end]
        );
        return rows[0] || null;
    }

    async function beginScheduleRun({
        companyId,
        schedule = null,
        scheduleKey,
        runType,
        triggerType,
        deduplicationKey,
        parentRunId = null,
        outputTypes = null,
        user = {}
    }) {
        try {
            const [result] = await pool.query(
                `INSERT INTO StackCTRLIntelligenceScheduleRuns
                 (CompanyID, ScheduleID, ScheduleKey, RunType, TriggerType,
                  DeduplicationKey, ParentRunID, RequestedOutputTypes, Status,
                  CreatedByUserID, CreatedByEmail)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?, ?)`,
                [
                    companyId,
                    schedule?.ID || null,
                    scheduleKey,
                    runType,
                    triggerType,
                    deduplicationKey,
                    parentRunId,
                    outputTypes ? JSON.stringify(outputTypes) : null,
                    user.id || user.userId || null,
                    user.email || null
                ]
            );
            return result.insertId;
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') return null;
            throw error;
        }
    }

    async function completeScheduleRun(runId, details = {}) {
        if (!runId) return;
        await pool.query(
            `UPDATE StackCTRLIntelligenceScheduleRuns
             SET Status = ?, SnapshotID = COALESCE(?, SnapshotID),
                 IntelligenceRunID = COALESCE(?, IntelligenceRunID),
                 CollectionSummaryJson = COALESCE(?, CollectionSummaryJson),
                 HistoricalContextJson = COALESCE(?, HistoricalContextJson),
                 ErrorMessage = ?, CompletedAt = NOW()
             WHERE ID = ?`,
            [
                details.status || 'completed',
                details.snapshotId || null,
                details.intelligenceRunId || null,
                details.collectionSummary ? JSON.stringify(details.collectionSummary) : null,
                details.historicalContext ? JSON.stringify(details.historicalContext) : null,
                details.errorMessage || null,
                runId
            ]
        );
    }

    async function runTenantDataCollection(companyId) {
        const built = await intelligenceService.buildTenantAIContext(companyId, {
            refresh: true,
            persistCapabilities: true
        });
        const collection = {
            companyId: Number(companyId),
            collectedAt: new Date().toISOString(),
            dataCompleteness: built.dataCompleteness,
            sourceStatuses: built.sources.map(source => ({
                sourceKey: source.sourceKey,
                status: source.status,
                isExpected: source.isExpected,
                freshness: source.freshness,
                warnings: source.warnings
            })),
            metrics: built.context.metrics
        };
        Object.defineProperty(collection, '_built', { value: built, enumerable: false });
        Object.defineProperty(collection, '_context', { value: built.context, enumerable: false });
        return collection;
    }

    async function createScheduledSnapshot(companyId, reason = 'hourly', collection = null) {
        if (collection?._built && typeof intelligenceService.createSnapshotFromBuiltContext === 'function') {
            return intelligenceService.createSnapshotFromBuiltContext({
                built: collection._built,
                snapshotType: `scheduled_${String(reason).slice(0, 60)}`
            });
        }
        return intelligenceService.createSnapshot({
            companyId,
            options: {
                snapshotType: `scheduled_${String(reason).slice(0, 60)}`,
                refresh: false,
                persistCapabilities: true
            }
        });
    }

    async function findNearestSnapshot(companyId, current, target) {
        if (target.key === 'previous') {
            const [rows] = await pool.query(
                `SELECT snapshot.*
                 FROM StackCTRLTenantEvidenceSnapshots snapshot
                 WHERE snapshot.ID = (
                    SELECT MAX(previous.ID)
                    FROM StackCTRLTenantEvidenceSnapshots previous
                    WHERE previous.CompanyID = ? AND previous.ID < ?
                 )
                 LIMIT 1`,
                [companyId, current.ID]
            );
            return rows[0] || null;
        }

        const targetAt = DateTime.fromJSDate(new Date(current.CreatedAt), { zone: 'utc' })
            .minus({ minutes: target.minutes })
            .toJSDate();
        const rangeStart = DateTime.fromJSDate(targetAt, { zone: 'utc' }).minus({ minutes: target.toleranceMinutes }).toJSDate();
        const rangeEnd = DateTime.fromJSDate(targetAt, { zone: 'utc' }).plus({ minutes: target.toleranceMinutes }).toJSDate();
        const [candidateRows] = await pool.query(
            `SELECT
                MAX(CASE WHEN CreatedAt <= ? THEN CreatedAt END) AS BeforeTarget,
                MIN(CASE WHEN CreatedAt >= ? THEN CreatedAt END) AS AfterTarget
             FROM StackCTRLTenantEvidenceSnapshots
             WHERE CompanyID = ? AND ID <> ? AND CreatedAt < ?
               AND CreatedAt BETWEEN ? AND ?`,
            [targetAt, targetAt, companyId, current.ID, current.CreatedAt, rangeStart, rangeEnd]
        );
        const timestamps = [candidateRows[0]?.BeforeTarget, candidateRows[0]?.AfterTarget].filter(Boolean);
        if (!timestamps.length) return null;
        const candidateAt = timestamps.sort((left, right) =>
            Math.abs(new Date(left).getTime() - targetAt.getTime()) - Math.abs(new Date(right).getTime() - targetAt.getTime())
        )[0];
        const [rows] = await pool.query(
            `SELECT snapshot.*
             FROM StackCTRLTenantEvidenceSnapshots snapshot
             WHERE snapshot.ID = (
                SELECT MAX(candidate.ID)
                FROM StackCTRLTenantEvidenceSnapshots candidate
                WHERE candidate.CompanyID = ? AND candidate.CreatedAt = ? AND candidate.ID <> ?
             )
             LIMIT 1`,
            [companyId, candidateAt, current.ID]
        );
        const candidate = rows[0] || null;
        if (!candidate) return null;
        candidate.TargetAt = targetAt;
        return candidate;
    }

    async function getHistoricalSnapshotContext(companyId, currentSnapshotId) {
        const [currentRows] = await pool.query(
            `SELECT * FROM StackCTRLTenantEvidenceSnapshots
             WHERE ID = ? AND CompanyID = ? LIMIT 1`,
            [currentSnapshotId, companyId]
        );
        if (!currentRows.length) throw new Error('Current snapshot not found');
        const current = currentRows[0];
        const currentMetrics = parseJson(current.MetricsJson, {});
        const comparisons = {};
        let historicalComparisonsStored = true;

        for (const target of HISTORICAL_TARGETS) {
            const baseline = await findNearestSnapshot(companyId, current, target);
            const baselineMetrics = baseline ? parseJson(baseline.MetricsJson, {}) : {};
            const metricChanges = baseline ? compareMetrics(currentMetrics, baselineMetrics) : {};
            const targetAt = target.key === 'previous'
                ? null
                : DateTime.fromJSDate(new Date(current.CreatedAt), { zone: 'utc' }).minus({ minutes: target.minutes }).toJSDate();
            const differenceMinutes = baseline && targetAt
                ? Math.round(Math.abs(new Date(baseline.CreatedAt).getTime() - targetAt.getTime()) / 60000)
                : null;

            if (historicalComparisonsStored) {
                try {
                    await pool.query(
                        `INSERT INTO StackCTRLIntelligenceHistoricalComparisons
                 (CompanyID, CurrentSnapshotID, ComparisonKey, TargetOffsetMinutes,
                  TargetAt, BaselineSnapshotID, BaselineCreatedAt, DifferenceMinutes,
                  AvailabilityStatus, CurrentMetricsJson, BaselineMetricsJson,
                  MetricChangesJson, WarningsJson)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                    TargetAt = VALUES(TargetAt),
                    BaselineSnapshotID = VALUES(BaselineSnapshotID),
                    BaselineCreatedAt = VALUES(BaselineCreatedAt),
                    DifferenceMinutes = VALUES(DifferenceMinutes),
                    AvailabilityStatus = VALUES(AvailabilityStatus),
                    CurrentMetricsJson = VALUES(CurrentMetricsJson),
                    BaselineMetricsJson = VALUES(BaselineMetricsJson),
                    MetricChangesJson = VALUES(MetricChangesJson),
                    WarningsJson = VALUES(WarningsJson)`,
                        [
                            companyId,
                            currentSnapshotId,
                            target.key,
                            target.minutes,
                            targetAt,
                            baseline?.ID || null,
                            baseline?.CreatedAt || null,
                            differenceMinutes,
                            baseline ? 'available' : 'unavailable',
                            JSON.stringify(currentMetrics),
                            baseline ? JSON.stringify(baselineMetrics) : null,
                            baseline ? JSON.stringify(metricChanges) : null,
                            JSON.stringify(baseline ? [] : [`No suitable ${target.key} snapshot is available yet.`])
                        ]
                    );
                } catch (error) {
                    if (error?.code !== 'ER_NO_SUCH_TABLE') throw error;
                    historicalComparisonsStored = false;
                    if (!historicalComparisonWarningShown) {
                        historicalComparisonWarningShown = true;
                        logger.warn('[StackCTRL Intelligence] Historical comparison table is missing; analysis will continue without persisting comparisons.');
                    }
                }
            }

            comparisons[target.key] = {
                comparisonKey: target.key,
                availability: baseline ? 'available' : 'unavailable',
                targetAt: targetAt ? targetAt.toISOString() : null,
                differenceMinutes,
                metricChanges,
                snapshot: serializeSnapshot(baseline)
            };
        }

        const currentSnapshot = serializeSnapshot(current);
        const historicalIntelligence = buildHistoricalIntelligence({ currentSnapshot, comparisons });
        return {
            currentSnapshot,
            comparisons,
            historicalIntelligence,
            persistence: {
                historicalComparisonsStored,
                warning: historicalComparisonsStored
                    ? null
                    : 'StackCTRLIntelligenceHistoricalComparisons is not installed; comparisons were calculated in memory only.'
            },
            instructions: {
                compareCurrentAgainstAvailableHistory: true,
                doNotInventMissingPeriods: true
            }
        };
    }

    async function runScheduledAzureAnalysis(companyId, snapshotId, outputTypes = DEFAULT_OUTPUT_TYPES, user = {}) {
        const historicalContext = await getHistoricalSnapshotContext(companyId, snapshotId);
        const analysis = await intelligenceService.analyseSnapshot({
            companyId,
            snapshotId,
            outputTypes,
            user,
            historicalContext
        });
        return { ...analysis, historicalContext };
    }

    async function getPreviousSnapshotMetrics(companyId, snapshotId) {
        const [rows] = await pool.query(
            `SELECT MetricsJson FROM StackCTRLTenantEvidenceSnapshots
             WHERE CompanyID = ? AND ID < ?
             ORDER BY ID DESC LIMIT 1`,
            [companyId, snapshotId]
        );
        return parseJson(rows[0]?.MetricsJson, {});
    }

    function findCriticalSignals(metrics, previousMetrics = {}) {
        const signals = [];
        const security = metrics.security_alerts || {};
        const criticalAlerts = numberFrom(security, ['criticalAlerts', 'CriticalAlerts']) || 0;
        const highAlerts = numberFrom(security, ['highSeverityAlerts', 'HighSeverityAlerts']) || 0;
        const activeIncidents = numberFrom(security, ['activeIncidents', 'ActiveIncidents']) || 0;
        if (criticalAlerts > 0 || highAlerts > 0 || activeIncidents >= 3) {
            signals.push({
                sourceKey: 'security_alerts',
                eventType: 'critical_security_activity',
                severity: criticalAlerts > 0 ? 'critical' : 'high',
                title: 'Critical security activity detected',
                description: `${criticalAlerts} critical alert(s), ${highAlerts} high-severity alert(s), and ${activeIncidents} active incident(s) are present.`,
                evidence: security
            });
        }

        const cloudflare = metrics.cloudflare_network_security || {};
        const previousCloudflare = previousMetrics.cloudflare_network_security || {};
        const denied = numberFrom(cloudflare, ['deniedAccessEvents']) || 0;
        const previousDenied = numberFrom(previousCloudflare, ['deniedAccessEvents']) || 0;
        if (denied >= 20 || (denied >= 10 && previousDenied > 0 && denied >= previousDenied * 2)) {
            signals.push({
                sourceKey: 'cloudflare_network_security',
                eventType: 'severe_access_spike',
                severity: 'critical',
                title: 'Severe Cloudflare access spike detected',
                description: `Denied access activity increased to ${denied} event(s).`,
                evidence: { deniedAccessEvents: denied, previousDeniedAccessEvents: previousDenied }
            });
        }

        const compliance = metrics.compliance || {};
        const previousCompliance = previousMetrics.compliance || {};
        const complianceScore = numberFrom(compliance, ['score', 'healthScore', 'complianceScore']);
        const previousComplianceScore = numberFrom(previousCompliance, ['score', 'healthScore', 'complianceScore']);
        if (complianceScore != null && (complianceScore <= 40 || (previousComplianceScore != null && previousComplianceScore - complianceScore >= 20))) {
            signals.push({
                sourceKey: 'compliance',
                eventType: 'major_compliance_drop',
                severity: 'critical',
                title: 'Major compliance posture drop detected',
                description: `Compliance score is ${complianceScore}${previousComplianceScore == null ? '' : `, previously ${previousComplianceScore}`}.`,
                evidence: { complianceScore, previousComplianceScore }
            });
        }

        const devices = metrics.devices || {};
        const previousDevices = previousMetrics.devices || {};
        const totalDevices = numberFrom(devices, ['TotalDevices', 'totalDevices']) || 0;
        const nonCompliant = numberFrom(devices, ['NonCompliant', 'nonCompliant']) || 0;
        const previousNonCompliant = numberFrom(previousDevices, ['NonCompliant', 'nonCompliant']) || 0;
        const nonCompliantRatio = totalDevices ? nonCompliant / totalDevices : 0;
        if ((totalDevices >= 5 && nonCompliantRatio >= 0.3) || nonCompliant - previousNonCompliant >= 10) {
            signals.push({
                sourceKey: 'devices',
                eventType: 'major_device_compliance_drop',
                severity: 'critical',
                title: 'Major device compliance drop detected',
                description: `${nonCompliant} of ${totalDevices} device(s) are non-compliant.`,
                evidence: { totalDevices, nonCompliant, previousNonCompliant }
            });
        }
        return signals;
    }

    async function detectCriticalIntelligenceTriggers(companyId, snapshotId) {
        const [rows] = await pool.query(
            `SELECT MetricsJson FROM StackCTRLTenantEvidenceSnapshots
             WHERE ID = ? AND CompanyID = ? LIMIT 1`,
            [snapshotId, companyId]
        );
        if (!rows.length) throw new Error('Snapshot not found for critical-event detection');
        const metrics = parseJson(rows[0].MetricsJson, {});
        const previousMetrics = await getPreviousSnapshotMetrics(companyId, snapshotId);
        const signals = findCriticalSignals(metrics, previousMetrics);
        const detected = [];
        const local = localTime();

        for (const signal of signals) {
            const deduplicationKey = criticalFingerprint(companyId, signal, local);
            try {
                const [result] = await pool.query(
                    `INSERT INTO StackCTRLIntelligenceCriticalEvents
                     (CompanyID, SnapshotID, SourceKey, EventType, Severity,
                      DeduplicationKey, Title, Description, EvidenceJson,
                      DeduplicationExpiresAt, Status)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR), 'detected')`,
                    [
                        companyId,
                        snapshotId,
                        signal.sourceKey,
                        signal.eventType,
                        signal.severity,
                        deduplicationKey,
                        signal.title,
                        signal.description,
                        JSON.stringify(signal.evidence || {})
                    ]
                );
                detected.push({ ...signal, id: result.insertId, deduplicationKey });
            } catch (error) {
                if (error.code !== 'ER_DUP_ENTRY') throw error;
            }
        }
        return detected;
    }

    async function markCriticalEventsAnalyzed(events, scheduleRunId, intelligenceRunId) {
        if (!events.length) return;
        await pool.query(
            `UPDATE StackCTRLIntelligenceCriticalEvents
             SET AnalysisTriggered = 1, ScheduleRunID = ?, IntelligenceRunID = ?,
                 Status = 'analysed'
             WHERE ID IN (?)`,
            [scheduleRunId, intelligenceRunId, events.map(event => event.id)]
        );
    }

    async function executeAuditedRun(options, task) {
        const runId = await beginScheduleRun(options);
        if (!runId) return { status: 'duplicate', scheduleKey: options.scheduleKey };
        try {
            const result = await task(runId);
            await completeScheduleRun(runId, { status: 'completed', ...result.audit });
            if (options.schedule?.ID) {
                await pool.query('UPDATE StackCTRLIntelligenceSchedules SET LastRunAt = NOW() WHERE ID = ?', [options.schedule.ID]);
            }
            return { status: 'completed', runId, ...result.value };
        } catch (error) {
            await completeScheduleRun(runId, { status: 'failed', errorMessage: error.message });
            logger.error(`[StackCTRL Intelligence Scheduler] ${options.scheduleKey} failed:`, error.message);
            return { status: 'failed', runId, message: error.message };
        }
    }

    async function runCriticalAnalysis(companyId, snapshotId, events, local, user = {}) {
        const scheduleKey = 'critical_analysis';
        const bucket = local.toFormat('yyyyLLddHH');
        return executeAuditedRun({
            companyId,
            scheduleKey,
            runType: 'analysis',
            triggerType: 'critical',
            deduplicationKey: makeDeduplicationKey(companyId, scheduleKey, bucket),
            outputTypes: DEFAULT_OUTPUT_TYPES,
            user
        }, async runId => {
            const analysis = await runScheduledAzureAnalysis(
                companyId,
                snapshotId,
                DEFAULT_OUTPUT_TYPES,
                user
            );
            await markCriticalEventsAnalyzed(events, runId, analysis.runId);
            return {
                audit: {
                    snapshotId,
                    intelligenceRunId: analysis.runId,
                    historicalContext: historicalAuditContext(analysis.historicalContext)
                },
                value: { snapshotId, intelligenceRunId: analysis.runId, criticalEvents: events.length }
            };
        });
    }

    function historicalAvailability(context) {
        return Object.fromEntries(Object.entries(context?.comparisons || {}).map(([key, value]) => [key, {
            availability: value.availability,
            snapshotId: value.snapshot?.snapshotId || null,
            targetAt: value.targetAt,
            differenceMinutes: value.differenceMinutes
        }]));
    }

    function historicalAuditContext(context) {
        if (!context) return null;
        return {
            availability: historicalAvailability(context),
            intelligence: context.historicalIntelligence || null
        };
    }

    async function runCompanySchedule(companyId, now = new Date()) {
        const local = localTime(now);
        const schedules = await ensureTenantSchedules(companyId);
        const enabled = new Map(schedules.filter(row => Number(row.IsEnabled) === 1).map(row => [row.ScheduleKey, row]));
        if (schedules.length && !enabled.size && !disabledSchedulesWarningShown) {
            disabledSchedulesWarningShown = true;
            logger.warn('[StackCTRL Intelligence Scheduler] All intelligence schedules are disabled; scheduled collection and analysis will remain idle.');
        }
        const results = [];
        const quarter = Math.floor(local.minute / 15) * 15;
        const collectionBucket = `${local.toFormat('yyyyLLddHH')}${String(quarter).padStart(2, '0')}`;

        const collectionSchedule = enabled.get('collection_15m');
        let collectionResult = null;
        if (collectionSchedule) {
            collectionResult = await executeAuditedRun({
                companyId,
                schedule: collectionSchedule,
                scheduleKey: 'collection_15m',
                runType: 'collection',
                triggerType: 'scheduled',
                deduplicationKey: makeDeduplicationKey(companyId, 'collection_15m', collectionBucket)
            }, async () => {
                const collection = await runTenantDataCollection(companyId);
                return {
                    audit: {
                        collectionSummary: {
                            collectedAt: collection.collectedAt,
                            dataCompleteness: collection.dataCompleteness,
                            sourceStatuses: collection.sourceStatuses,
                            context: collection._context
                        }
                    },
                    value: { collection }
                };
            });
            results.push(collectionResult);
        }

        const hourlyDue = local.minute < 15;
        const analysisDue = hourlyDue && ANALYSIS_HOURS.has(local.hour);
        let snapshotId = null;
        let criticalEvents = [];
        const snapshotSchedule = enabled.get('snapshot_hourly');

        if (hourlyDue && snapshotSchedule) {
            const hourBucket = local.toFormat('yyyyLLddHH');
            const snapshotResult = await executeAuditedRun({
                companyId,
                schedule: snapshotSchedule,
                scheduleKey: 'snapshot_hourly',
                runType: 'snapshot',
                triggerType: 'scheduled',
                deduplicationKey: makeDeduplicationKey(companyId, 'snapshot_hourly', hourBucket)
            }, async () => {
                const snapshot = await createScheduledSnapshot(companyId, 'hourly', collectionResult?.collection || null);
                return { audit: { snapshotId: snapshot.snapshotId }, value: { snapshot } };
            });
            results.push(snapshotResult);
            snapshotId = snapshotResult.snapshot?.snapshotId || snapshotResult.snapshotId || null;
            if (!snapshotId && snapshotResult.status === 'duplicate') {
                const existing = await preventDuplicateScheduledRuns(companyId, 'snapshot_hourly', {
                    start: local.startOf('hour').toUTC().toJSDate(),
                    end: local.endOf('hour').toUTC().toJSDate()
                });
                snapshotId = existing?.SnapshotID || null;
            }
            if (snapshotId) criticalEvents = await detectCriticalIntelligenceTriggers(companyId, snapshotId);
        }

        if (!snapshotId && collectionResult?.collection?._context) {
            const previousRows = await pool.query(
                `SELECT MetricsJson FROM StackCTRLTenantEvidenceSnapshots
                 WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 1`,
                [companyId]
            );
            const previousMetrics = parseJson(previousRows[0][0]?.MetricsJson, {});
            const signals = findCriticalSignals(collectionResult.collection._context.metrics, previousMetrics);
            if (signals.length) {
                const existingCritical = await preventDuplicateScheduledRuns(companyId, 'critical_analysis', {
                    start: local.startOf('hour').toUTC().toJSDate(),
                    end: local.endOf('hour').toUTC().toJSDate()
                });
                if (!existingCritical) {
                    const snapshot = await createScheduledSnapshot(companyId, 'critical_event', collectionResult.collection);
                    snapshotId = snapshot.snapshotId;
                    criticalEvents = await detectCriticalIntelligenceTriggers(companyId, snapshotId);
                }
            }
        }

        const analysisSchedule = enabled.get('azure_analysis');
        if (analysisDue && analysisSchedule && snapshotId) {
            const hourBucket = local.toFormat('yyyyLLddHH');
            const outputTypes = parseJson(analysisSchedule.OutputTypesJson, DEFAULT_OUTPUT_TYPES);
            const analysisResult = await executeAuditedRun({
                companyId,
                schedule: analysisSchedule,
                scheduleKey: 'azure_analysis',
                runType: 'analysis',
                triggerType: 'scheduled',
                deduplicationKey: makeDeduplicationKey(companyId, 'azure_analysis', hourBucket),
                outputTypes
            }, async runId => {
                const analysis = await runScheduledAzureAnalysis(companyId, snapshotId, outputTypes);
                await markCriticalEventsAnalyzed(criticalEvents, runId, analysis.runId);
                return {
                    audit: {
                        snapshotId,
                        intelligenceRunId: analysis.runId,
                        historicalContext: historicalAuditContext(analysis.historicalContext)
                    },
                    value: { snapshotId, intelligenceRunId: analysis.runId }
                };
            });
            results.push(analysisResult);
        } else if (criticalEvents.length && snapshotId) {
            results.push(await runCriticalAnalysis(companyId, snapshotId, criticalEvents, local));
        }
        return results;
    }

    async function runScheduledTick({ companyId = null, now = new Date() } = {}) {
        const local = localTime(now);
        if (!isBusinessTime(local)) {
            return { status: 'outside_business_hours', localTime: local.toISO(), companies: [] };
        }

        let companies;
        if (companyId) companies = [{ ID: Number(companyId) }];
        else [companies] = await pool.query('SELECT ID FROM Companies ORDER BY ID');
        const companyResults = [];
        for (const company of companies) {
            companyResults.push({
                companyId: company.ID,
                runs: await runCompanySchedule(company.ID, now)
            });
        }
        return { status: 'completed', localTime: local.toISO(), companies: companyResults };
    }

    async function runNow({ companyId, includeAnalysis = false, outputTypes = DEFAULT_OUTPUT_TYPES, user = {} }) {
        const local = localTime();
        const deduplicationKey = makeDeduplicationKey(companyId, 'manual_run', `${Date.now()}:${user.id || user.userId || 'admin'}`);
        return executeAuditedRun({
            companyId,
            scheduleKey: 'manual_run',
            runType: 'orchestration',
            triggerType: 'manual',
            deduplicationKey,
            outputTypes: includeAnalysis ? outputTypes : null,
            user
        }, async runId => {
            const collection = await runTenantDataCollection(companyId);
            const snapshot = await createScheduledSnapshot(companyId, 'manual', collection);
            const criticalEvents = await detectCriticalIntelligenceTriggers(companyId, snapshot.snapshotId);
            let analysis = null;
            if (includeAnalysis) {
                analysis = await runScheduledAzureAnalysis(companyId, snapshot.snapshotId, outputTypes, user);
                await markCriticalEventsAnalyzed(criticalEvents, runId, analysis.runId);
            } else if (criticalEvents.length) {
                analysis = await runCriticalAnalysis(companyId, snapshot.snapshotId, criticalEvents, local, user);
            }
            return {
                audit: {
                    snapshotId: snapshot.snapshotId,
                    intelligenceRunId: analysis?.runId || analysis?.intelligenceRunId || null,
                    collectionSummary: {
                        collectedAt: collection.collectedAt,
                        dataCompleteness: collection.dataCompleteness,
                        sourceStatuses: collection.sourceStatuses,
                        context: collection._context
                    },
                    historicalContext: historicalAuditContext(analysis?.historicalContext)
                },
                value: {
                    collection: { collectedAt: collection.collectedAt, dataCompleteness: collection.dataCompleteness, sourceStatuses: collection.sourceStatuses },
                    snapshot,
                    analysis,
                    criticalEvents
                }
            };
        });
    }

    async function getSchedulerStatus(companyId = null) {
        const params = [];
        const where = companyId ? 'WHERE CompanyID = ?' : '';
        if (companyId) params.push(companyId);
        const [recentRuns, failedRuns, snapshotRows, analysisRows] = await Promise.all([
            pool.query(`SELECT * FROM StackCTRLIntelligenceScheduleRuns ${where || 'WHERE 1=1'} AND RunType <> 'graph_collection_claim' ORDER BY StartedAt DESC LIMIT 100`, params),
            pool.query(`SELECT * FROM StackCTRLIntelligenceScheduleRuns ${where}${where ? ' AND' : ' WHERE'} Status = 'failed' ORDER BY StartedAt DESC LIMIT 50`, params),
            pool.query(`SELECT CompanyID, MAX(CreatedAt) AS LastSnapshotAt FROM StackCTRLTenantEvidenceSnapshots ${where} GROUP BY CompanyID`, params),
            pool.query(`SELECT CompanyID, MAX(CreatedAt) AS LastAnalysisAt FROM StackCTRLTenantAIOutputs ${where} GROUP BY CompanyID`, params)
        ]);
        return {
            recentRuns: recentRuns[0],
            failedRuns: failedRuns[0],
            lastSnapshots: snapshotRows[0],
            lastAnalyses: analysisRows[0]
        };
    }

    async function getHistory(companyId, limit = 100) {
        const safeLimit = Math.max(1, Math.min(250, Number(limit) || 100));
        const snapshots = await pool.query(
                `SELECT ID, CompanyID, TenantKey, PeriodStart, PeriodEnd, SnapshotType,
                        DataCompletenessScore, CreatedAt,
                        JSON_EXTRACT(MetricsJson, '$.stackctrl_risk') AS StackCTRLRiskJson,
                        JSON_EXTRACT(MetricsJson, '$.executive_kpis') AS ExecutiveKPIsJson
                 FROM StackCTRLTenantEvidenceSnapshots
                 WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT ?`,
                [companyId, safeLimit]
            );
        let comparisons;
        try {
            comparisons = await pool.query(
                `SELECT CurrentSnapshotID, ComparisonKey, TargetAt, BaselineSnapshotID,
                        BaselineCreatedAt, DifferenceMinutes, AvailabilityStatus,
                        MetricChangesJson, WarningsJson, CreatedAt
                 FROM StackCTRLIntelligenceHistoricalComparisons
                 WHERE CompanyID = ? ORDER BY CreatedAt DESC LIMIT 500`,
                [companyId]
            );
        } catch (error) {
            if (error?.code !== 'ER_NO_SUCH_TABLE') throw error;
            comparisons = [[], []];
        }
        const comparisonBySnapshot = comparisons[0].reduce((map, comparison) => {
            if (!map[comparison.CurrentSnapshotID]) map[comparison.CurrentSnapshotID] = {};
            map[comparison.CurrentSnapshotID][comparison.ComparisonKey] = {
                ...comparison,
                metricChanges: parseJson(comparison.MetricChangesJson, {}),
                warnings: parseJson(comparison.WarningsJson, [])
            };
            return map;
        }, {});
        return {
            companyId: Number(companyId),
            snapshots: snapshots[0].map(snapshot => ({
                ...snapshot,
                risk: parseJson(snapshot.StackCTRLRiskJson, {}),
                executiveKPIs: parseJson(snapshot.ExecutiveKPIsJson, {}),
                historicalComparisons: comparisonBySnapshot[snapshot.ID] || {}
            }))
        };
    }

    return {
        runTenantDataCollection,
        createScheduledSnapshot,
        getHistoricalSnapshotContext,
        runScheduledAzureAnalysis,
        detectCriticalIntelligenceTriggers,
        preventDuplicateScheduledRuns,
        runScheduledTick,
        runNow,
        getSchedulerStatus,
        getHistory,
        ensureTenantSchedules,
        findCriticalSignals
    };
}

module.exports = {
    DEFAULT_OUTPUT_TYPES,
    TIME_ZONE,
    createStackCTRLIntelligenceScheduler
};
