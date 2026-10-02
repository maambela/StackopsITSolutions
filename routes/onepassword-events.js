const express = require('express');

function createOnePasswordEventsRouter({ authenticateToken, getAccessContextByUser, onePasswordEventsService, logger = console } = {}) {
    const router = express.Router();
    router.use(authenticateToken);

    router.post('/sync', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const context = await getAccessContextByUser(req.user);
            if (!context?.companyId) {
                return res.status(403).json({ success: false, message: 'Tenant access is not configured for this account.' });
            }

            const hasSunbirdAccess = Boolean(
                context.hasSunbirdAccess ||
                String(context.accessType || '').toLowerCase() === 'sunbird'
            );
            if (!hasSunbirdAccess) {
                return res.status(403).json({ success: false, message: '1Password activity is not available for this account.' });
            }

            const result = await onePasswordEventsService.syncCompany(context.companyId);
            return res.json(result);
        } catch (error) {
            const statusCode = Number(error.statusCode);
            const status = Number.isInteger(statusCode) && statusCode >= 400 && statusCode <= 599 ? statusCode : 500;
            const message = error.publicMessage || 'Unable to retrieve 1Password activity right now. Please try again later.';
            logger.error(`[1Password Events] API request failed (${error.code || 'request_error'}, HTTP ${status}).`);
            return res.status(status).json({ success: false, message });
        }
    });

    return router;
}

module.exports = { createOnePasswordEventsRouter };
