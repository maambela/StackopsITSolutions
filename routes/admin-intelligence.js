const express = require('express');
const { snapshotFailureCode, withSnapshotSqlRequest } = require('../services/intelligence/sql-payload-diagnostics');

const snapshotFailureMessages = {
    SNAPSHOT_SQL_PAYLOAD_TOO_LARGE: 'Snapshot data exceeds the database packet limit. The previous snapshot remains available.',
    SNAPSHOT_DATABASE_UNAVAILABLE: 'The database connection was interrupted during snapshot creation.',
    SNAPSHOT_COMMIT_OUTCOME_UNKNOWN: 'Snapshot commit could not be verified. Check the latest snapshot before trying again.',
    SNAPSHOT_CREATION_FAILED: 'Snapshot creation failed.'
};

function createAdminIntelligenceRouter({ authenticateToken, adminIntelligenceService, enterpriseIntelligenceService = null } = {}) {
    if (!authenticateToken || !adminIntelligenceService) {
        throw new Error('Admin Intelligence router requires authentication and service dependencies');
    }
    const router = express.Router();

    router.use(authenticateToken);
    router.use((req, res, next) => {
        if (String(req.user?.role || '').toLowerCase() !== 'admin') {
            return res.status(403).json({ success: false, message: 'Administrator access is required' });
        }
        next();
    });

    function sendError(res, error, label) {
        console.error(`[StackCTRL Admin Intelligence] ${label}:`, error.message);
        const rateLimited = error?.enterpriseStatus === 'failed_rate_limited' || error?.azureMetadata?.rateLimited;
        const retryAfterMs = Number(error?.azureMetadata?.retryAfterMs || error?.azureMetadata?.lastRetryDelayMs || 0) || null;
        if (rateLimited) {
            return res.status(429).json({
                success: false,
                status: 'failed_rate_limited',
                message: error.message || 'Azure is temporarily rate limited. Retry after the indicated cooldown.',
                retryAfterMs
            });
        }
        res.status(error.statusCode || 500).json({ success: false, message: error.message });
    }

    function companyIdFrom(req, res) {
        const companyId = Number(req.params.companyId);
        if (!Number.isInteger(companyId) || companyId <= 0) {
            res.status(400).json({ success: false, message: 'A valid companyId is required' });
            return null;
        }
        return companyId;
    }

    function requireEnterprise(res) {
        if (enterpriseIntelligenceService) return true;
        res.status(503).json({ success: false, message: 'Enterprise Deep Reporting is not configured' });
        return false;
    }

    router.get('/status', async (_req, res) => {
        try {
            res.json({ success: true, ...(await adminIntelligenceService.getSystemStatus()) });
        } catch (error) {
            sendError(res, error, 'Status lookup failed');
        }
    });

    router.get('/tenants', async (_req, res) => {
        try {
            res.json({ success: true, tenants: await adminIntelligenceService.getTenants() });
        } catch (error) {
            sendError(res, error, 'Tenant lookup failed');
        }
    });

    router.get('/tenant/:companyId', async (req, res) => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            res.json({ success: true, ...(await adminIntelligenceService.getTenant(companyId)) });
        } catch (error) {
            sendError(res, error, 'Tenant intelligence lookup failed');
        }
    });

    router.post('/tenant/:companyId/snapshot', (req, res) => withSnapshotSqlRequest(async requestId => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const result = await adminIntelligenceService.createSnapshot(companyId, req.user);
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            const code = snapshotFailureCode(error);
            res.status(500).json({ success: false, code, message: snapshotFailureMessages[code], requestId });
        }
    }));

    router.post('/tenant/:companyId/analyze', async (req, res) => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const result = await adminIntelligenceService.runAnalysis(companyId, req.body || {}, req.user);
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Azure analysis failed');
        }
    });

    router.post('/tenant/:companyId/compact-context', async (req, res) => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const result = await adminIntelligenceService.buildCompactContext(companyId, req.body || {}, req.user);
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Compact context creation failed');
        }
    });

    router.post('/tenant/:companyId/period/:periodType', async (req, res) => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const periodType = String(req.params.periodType || '').toLowerCase();
            if (!['daily', 'weekly', 'monthly', 'yearly'].includes(periodType)) {
                return res.status(400).json({ success: false, message: 'Period type must be daily, weekly, monthly, or yearly' });
            }
            const result = await adminIntelligenceService.runPeriod(companyId, periodType, req.body || {}, req.user);
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Period intelligence run failed');
        }
    });

    router.post('/tenant/:companyId/full-test', async (req, res) => {
        try {
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const result = await adminIntelligenceService.runFullTest(companyId, req.body || {}, req.user);
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Full intelligence test failed');
        }
    });

    router.get('/tenant/:companyId/enterprise', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const runId = req.query.runId ? Number(req.query.runId) : null;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getAdminProgress(companyId, runId)) });
        } catch (error) {
            sendError(res, error, 'Enterprise intelligence lookup failed');
        }
    });

    router.get('/tenant/:companyId/enterprise/domain/:domainKey', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, domain: await enterpriseIntelligenceService.getAdminDomainDetail(companyId, req.params.domainKey, req.query.runId || null) });
        } catch (error) { sendError(res, error, 'Enterprise domain detail lookup failed'); }
    });

    router.get('/tenant/:companyId/enterprise/audit/:domainKey', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, audit: await enterpriseIntelligenceService.getAdminAuditDetail(companyId, req.params.domainKey, req.query.runId || null) });
        } catch (error) { sendError(res, error, 'Enterprise audit detail lookup failed'); }
    });

    router.get('/tenant/:companyId/enterprise/batches/:domainKey', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, batches: await enterpriseIntelligenceService.getAdminBatchDetails(companyId, req.params.domainKey, req.query.runId || null) });
        } catch (error) { sendError(res, error, 'Enterprise batch detail lookup failed'); }
    });

    router.get('/tenant/:companyId/enterprise/synthesis/:runId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, synthesis: await enterpriseIntelligenceService.getAdminSynthesisDetail(companyId, Number(req.params.runId)) });
        } catch (error) { sendError(res, error, 'Enterprise synthesis detail lookup failed'); }
    });

    router.get('/powerbi/intelligence/latest/:companyId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIIntelligenceRun(companyId, req.query.runId || null, { periodType: req.query.periodType || null })) });
        } catch (error) { sendError(res, error, 'Power BI intelligence lookup failed'); }
    });

    router.get('/powerbi/intelligence/domain/:companyId/:domainKey', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIDomain(companyId, req.params.domainKey, { runId: req.query.runId || null, periodType: req.query.periodType || null })) });
        } catch (error) { sendError(res, error, 'Power BI domain intelligence lookup failed'); }
    });

    router.get('/powerbi/intelligence/final/:companyId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIFinal(companyId, req.query.runId || null, { periodType: req.query.periodType || null })) });
        } catch (error) { sendError(res, error, 'Power BI enterprise synthesis lookup failed'); }
    });

    router.get('/powerbi/intelligence/final/:companyId/run/:runId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIFinal(companyId, Number(req.params.runId))) });
        } catch (error) { sendError(res, error, 'Power BI enterprise synthesis run lookup failed'); }
    });

    router.get('/powerbi/intelligence/history/:companyId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIHistory(companyId, { periodType: req.query.periodType || null, limit: req.query.limit })) });
        } catch (error) { sendError(res, error, 'Power BI intelligence history lookup failed'); }
    });

    router.get('/powerbi/raw/latest/:companyId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIRaw(companyId)) });
        } catch (error) { sendError(res, error, 'Power BI raw StackCTRL lookup failed'); }
    });

    router.get('/powerbi/raw/domain/:companyId/:domainKey', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            res.json({ success: true, ...(await enterpriseIntelligenceService.getPowerBIRaw(companyId, req.params.domainKey)) });
        } catch (error) { sendError(res, error, 'Power BI raw domain lookup failed'); }
    });

    router.get('/powerbi/tables/latest/:companyId', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res); if (!companyId) return;
            const result = await enterpriseIntelligenceService.getPowerBIIntelligenceRun(companyId, req.query.runId || null, { periodType: req.query.periodType || null });
            res.json({
                success: true, dataClassification: 'derived_intelligence_tables', companyId,
                snapshotId: result.latestSnapshotId, runId: result.latestRunId,
                periodType: result.periodType, periodStart: result.periodStart, periodEnd: result.periodEnd,
                createdAt: result.createdAt, tables: result.tables
            });
        } catch (error) { sendError(res, error, 'Power BI flattened table lookup failed'); }
    });

    router.post('/tenant/:companyId/enterprise/run', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const result = await enterpriseIntelligenceService.runEnterpriseReport({
                companyId,
                snapshotId: req.body?.snapshotId || null,
                periodType: req.body?.periodType || 'daily',
                domainKeys: req.body?.domainKeys || null,
                includeSynthesis: req.body?.includeSynthesis !== false,
                refreshSnapshot: req.body?.refreshSnapshot,
                user: req.user || {}
            });
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Enterprise Deep Reporting run failed');
        }
    });

    router.post('/tenant/:companyId/enterprise/domain', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const domainKeys = Array.isArray(req.body?.domainKeys)
                ? req.body.domainKeys
                : req.body?.domainKey ? [String(req.body.domainKey)] : enterpriseIntelligenceService.domains.filter(domain => domain.includedInCurrentPhase).map(domain => domain.key);
            const result = await enterpriseIntelligenceService.runEnterpriseReport({
                companyId,
                snapshotId: req.body?.snapshotId || null,
                periodType: req.body?.periodType || 'daily',
                domainKeys,
                includeSynthesis: false,
                refreshSnapshot: domainKeys.length > 1 ? req.body?.refreshSnapshot : false,
                user: req.user || {}
            });
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Enterprise domain analysis failed');
        }
    });


    router.post('/tenant/:companyId/enterprise/:runId/publish-report', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const runId = Number(req.params.runId);
            if (!Number.isInteger(runId) || runId <= 0) return res.status(400).json({ success: false, message: 'A valid completed enterprise run ID is required' });
            const result = await enterpriseIntelligenceService.publishCompletedRun({ companyId, runId });
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Completed enterprise report publication failed');
        }
    });

    router.post('/tenant/:companyId/enterprise/synthesis', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const runId = Number(req.body?.runId);
            if (!Number.isInteger(runId) || runId <= 0) {
                return res.status(400).json({ success: false, message: 'A completed enterprise runId is required' });
            }
            const result = await enterpriseIntelligenceService.runEnterpriseSynthesis({ companyId, runId });
            res.status(201).json({ success: true, runId, ...result });
        } catch (error) {
            sendError(res, error, 'Enterprise synthesis failed');
        }
    });

    router.post('/tenant/:companyId/enterprise/rollup/:periodType', async (req, res) => {
        try {
            if (!requireEnterprise(res)) return;
            const companyId = companyIdFrom(req, res);
            if (!companyId) return;
            const periodType = String(req.params.periodType || '').toLowerCase();
            if (!['weekly', 'monthly', 'yearly'].includes(periodType)) {
                return res.status(400).json({ success: false, message: 'Enterprise rollup must be weekly, monthly, or yearly' });
            }
            const result = await enterpriseIntelligenceService.runRollupReport({ companyId, periodType });
            res.status(201).json({ success: true, ...result });
        } catch (error) {
            sendError(res, error, 'Enterprise rollup failed');
        }
    });

    return router;
}

module.exports = { createAdminIntelligenceRouter };
