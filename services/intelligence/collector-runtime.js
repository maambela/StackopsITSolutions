'use strict';

function timeoutError({ sourceKey, companyId, timeoutMs, runId = null, pipelineExecutionId = null }) {
    const error = new Error(sourceKey + ' collector exceeded ' + timeoutMs + 'ms.');
    error.code = 'STACKCTRL_COLLECTOR_TIMEOUT';
    error.sourceKey = sourceKey;
    error.companyId = Number(companyId);
    error.runId = runId == null ? null : Number(runId);
    error.pipelineExecutionId = pipelineExecutionId || null;
    error.timeoutMs = timeoutMs;
    return error;
}

function createTrackedCollectorRegistry({ logger = console, now = () => Date.now(), timeoutMs = 60000, retainUntilSettled = false } = {}) {
    const entries = new Map();
    const emit = (event, details = {}) => logger.info?.('[StackCTRL Collector]', {
        event,
        timestamp: new Date(now()).toISOString(),
        ...details
    });

    async function run({ companyId, sourceKey, collectionTrigger, runId = null, pipelineExecutionId = null, signal = null, execute, timeout = timeoutMs, attemptId = null } = {}) {
        const key = String(companyId);
        const trace = attemptId ? { attemptId } : {};
        const deadlineMs = Math.max(1000, Number(timeout) || timeoutMs);
        const existing = entries.get(key);
        if (existing) {
            const ageMs = Math.max(0, now() - existing.startedAt);
            if (retainUntilSettled || ageMs < existing.timeoutMs) {
                emit('snapshot_source_refresh_joined', { ...trace, ...(existing.attemptId ? { ownerAttemptId: existing.attemptId } : {}), companyId: Number(companyId), runId, pipelineExecutionId, sourceKey, collectionTrigger, ageMs, ownerRunId: existing.runId, ownerPipelineExecutionId: existing.pipelineExecutionId });
                return existing.promise;
            }
            const error = timeoutError({ sourceKey: existing.sourceKey, companyId, timeoutMs: existing.timeoutMs, runId: existing.runId, pipelineExecutionId: existing.pipelineExecutionId });
            existing.controller.abort(error);
            entries.delete(key);
            emit('snapshot_source_refresh_timeout', { ...(existing.attemptId ? { attemptId: existing.attemptId } : {}), companyId: Number(companyId), runId: existing.runId, pipelineExecutionId: existing.pipelineExecutionId, sourceKey: existing.sourceKey, collectionTrigger: existing.collectionTrigger, elapsedMs: ageMs, timeoutMs: existing.timeoutMs, reusedStalePromise: true, error: error.message });
        }

        const controller = new AbortController();
        if (signal?.aborted) controller.abort(signal.reason);
        const abort = () => controller.abort(signal.reason);
        if (!signal?.aborted) signal?.addEventListener('abort', abort, { once: true });
        const startedAt = now();
        let timer = null;
        const entry = { controller, startedAt, timeoutMs: deadlineMs, sourceKey, collectionTrigger, runId, pipelineExecutionId, attemptId, promise: null };
        const deadline = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const error = timeoutError({ sourceKey, companyId, timeoutMs: deadlineMs, runId, pipelineExecutionId });
                controller.abort(error);
                emit('snapshot_source_refresh_timeout', { ...trace, companyId: Number(companyId), runId, pipelineExecutionId, sourceKey, collectionTrigger, elapsedMs: Math.max(0, now() - startedAt), timeoutMs: deadlineMs, error: error.message });
                reject(error);
            }, deadlineMs);
        });
        emit('snapshot_source_refresh_started', { ...trace, companyId: Number(companyId), runId, pipelineExecutionId, sourceKey, collectionTrigger, elapsedMs: 0 });
        const operation = Promise.resolve().then(() => execute({ signal: controller.signal, controller }));
        if (retainUntilSettled) {
            const clearEntry = () => {
                if (entries.get(key) === entry) entries.delete(key);
            };
            operation.then(clearEntry, clearEntry);
        }
        entry.promise = Promise.race([operation, deadline])
            .then(result => {
                const skipped = attemptId && result?.status === 'already_running';
                emit(skipped ? 'snapshot_source_refresh_skipped' : 'snapshot_source_refresh_completed', {
                    ...trace, ...(skipped ? { reason: result.status } : {}), companyId: Number(companyId), runId,
                    pipelineExecutionId, sourceKey, collectionTrigger, elapsedMs: Math.max(0, now() - startedAt)
                });
                return result;
            })
            .catch(error => {
                if (error?.code !== 'STACKCTRL_COLLECTOR_TIMEOUT') {
                    emit('snapshot_source_refresh_failed', {
                        ...trace, companyId: Number(companyId), runId, pipelineExecutionId, sourceKey, collectionTrigger,
                        elapsedMs: Math.max(0, now() - startedAt),
                        ...(attemptId ? { errorCode: error?.code || 'IDENTITY_COLLECTION_FAILED' } : { error: String(error?.message || error) })
                    });
                }
                throw error;
            })
            .finally(() => {
                clearTimeout(timer);
                signal?.removeEventListener('abort', abort);
                if (!retainUntilSettled && entries.get(key) === entry) entries.delete(key);
            });
        entries.set(key, entry);
        return entry.promise;
    }

    return { run, entries };
}


function operationTimeoutError(label, timeoutMs) {
    const error = new Error(label + ' exceeded ' + timeoutMs + 'ms.');
    error.code = 'STACKCTRL_OPERATION_TIMEOUT';
    error.timeoutMs = timeoutMs;
    return error;
}

async function runAbortableOperation({ operation, timeoutMs = 15000, signal = null, onTimeout = null, label = 'Operation' } = {}) {
    if (typeof operation !== 'function') throw new Error('operation must be a function');
    const deadlineMs = Math.max(1000, Number(timeoutMs) || 15000);
    const controller = new AbortController();
    let timer = null;
    let abortListener = null;
    if (signal?.aborted) controller.abort(signal.reason);
    else if (signal?.addEventListener) {
        abortListener = () => controller.abort(signal.reason);
        signal.addEventListener('abort', abortListener, { once: true });
    }
    const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => {
            const error = operationTimeoutError(label, deadlineMs);
            try { onTimeout?.(error); } catch (_) {}
            controller.abort(error);
            reject(error);
        }, deadlineMs);
    });
    try {
        return await Promise.race([Promise.resolve().then(() => operation({ signal: controller.signal })), deadline]);
    } finally {
        clearTimeout(timer);
        if (abortListener && signal?.removeEventListener) signal.removeEventListener('abort', abortListener);
    }
}

async function acquireConnectionWithDeadline(pool, { timeoutMs = 30000, signal = null, label = 'Database connection' } = {}) {
    if (!pool || typeof pool.getConnection !== 'function') throw new Error('Database pool does not support getConnection');
    let deadlinePassed = false;
    const acquisition = Promise.resolve().then(() => pool.getConnection()).then(connection => {
        if (deadlinePassed) {
            if (typeof connection.release === 'function') connection.release();
            else if (typeof connection.destroy === 'function') connection.destroy();
            throw operationTimeoutError(label, Math.max(1000, Number(timeoutMs) || 30000));
        }
        return connection;
    });
    try {
        return await runAbortableOperation({ operation: () => acquisition, timeoutMs, signal, label, onTimeout: () => { deadlinePassed = true; } });
    } catch (error) {
        deadlinePassed = true;
        throw error;
    }
}

async function runDatabaseOperationWithDeadline({ connection, operation, timeoutMs = 30000, signal = null, label = 'Database operation' } = {}) {
    return runAbortableOperation({
        operation,
        timeoutMs,
        signal,
        label,
        onTimeout: () => {
            if (connection && typeof connection.destroy === 'function') connection.destroy();
        }
    });
}

module.exports = { createTrackedCollectorRegistry, timeoutError, operationTimeoutError, runAbortableOperation, acquireConnectionWithDeadline, runDatabaseOperationWithDeadline };
