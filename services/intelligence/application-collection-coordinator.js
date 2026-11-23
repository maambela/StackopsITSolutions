'use strict';

function createApplicationCollectionCoordinator({
    payloadTtlMs = 15 * 60 * 1000,
    assignmentTtlMs = 60 * 60 * 1000,
    now = () => Date.now(),
    logger = console
} = {}) {
    const safePayloadTtlMs = Math.max(1000, Number(payloadTtlMs) || 15 * 60 * 1000);
    const safeAssignmentTtlMs = Math.max(1000, Number(assignmentTtlMs) || 60 * 60 * 1000);
    const payloads = new Map();
    const payloadPromises = new Map();
    const assignments = new Map();
    const assignmentPromises = new Map();

    function isCompleteApplicationsPayload(payload) {
        return Boolean(payload && payload.success === true && Array.isArray(payload.applications));
    }

    async function runPayload(key, operation, { forceRefresh = false } = {}) {
        const scopeKey = String(key || 'default');
        const cached = payloads.get(scopeKey);
        if (payloadPromises.has(scopeKey)) {
            logger.info?.('[Applications Collection] Joined application payload collection', { scopeKey });
            return payloadPromises.get(scopeKey);
        }
        if (!forceRefresh && cached && cached.expiresAt > now()) {
            logger.info?.('[Applications Collection] Reused complete application payload', { scopeKey });
            return cached.payload;
        }

        const promise = Promise.resolve()
            .then(operation)
            .then(payload => {
                if (isCompleteApplicationsPayload(payload)) {
                    payloads.set(scopeKey, { payload, expiresAt: now() + safePayloadTtlMs });
                }
                return payload;
            })
            .finally(() => {
                if (payloadPromises.get(scopeKey) === promise) payloadPromises.delete(scopeKey);
            });
        payloadPromises.set(scopeKey, promise);
        return promise;
    }

    async function runAssignment(key, operation, { forceRefresh = false } = {}) {
        const scopeKey = String(key || 'default');
        const cached = assignments.get(scopeKey);
        if (assignmentPromises.has(scopeKey)) {
            logger.info?.('[Applications Collection] Joined application assignment collection', { scopeKey });
            return assignmentPromises.get(scopeKey);
        }
        if (!forceRefresh && cached && cached.expiresAt > now()) {
            logger.info?.('[Applications Collection] Reused complete application assignments', { scopeKey });
            return cached.assignments;
        }

        const promise = Promise.resolve()
            .then(operation)
            .then(value => {
                const assignmentRows = Array.isArray(value) ? value : null;
                if (assignmentRows) assignments.set(scopeKey, { assignments: assignmentRows, expiresAt: now() + safeAssignmentTtlMs });
                return assignmentRows || [];
            })
            .finally(() => {
                if (assignmentPromises.get(scopeKey) === promise) assignmentPromises.delete(scopeKey);
            });
        assignmentPromises.set(scopeKey, promise);
        return promise;
    }

    return {
        runPayload,
        runAssignment,
        isCompleteApplicationsPayload,
        getStatus: () => ({
            payloadEntries: payloads.size,
            payloadPromises: payloadPromises.size,
            assignmentEntries: assignments.size,
            assignmentPromises: assignmentPromises.size,
            payloadTtlMs: safePayloadTtlMs,
            assignmentTtlMs: safeAssignmentTtlMs
        })
    };
}

module.exports = { createApplicationCollectionCoordinator };
