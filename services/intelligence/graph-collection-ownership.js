const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash, randomUUID } = require('node:crypto');

const ownership = new AsyncLocalStorage();
const dbTime = 'UNIX_TIMESTAMP(CURRENT_TIMESTAMP(3)) * 1000';
const expiry = "COALESCE(JSON_EXTRACT(CollectionSummaryJson, '$.expiresAt') + 0, 0)";
const owner = "JSON_UNQUOTE(JSON_EXTRACT(CollectionSummaryJson, '$.owner'))";
const kind = 'graph_collection_claim';

function claimKey(companyId, tenantId, source) {
    const digest = createHash('sha256').update(JSON.stringify([Number(companyId), tenantId.trim().toLowerCase(), source])).digest('hex');
    return 'graph-collection:' + digest;
}

function validClaim(claim) {
    return [claim.key, kind, claim.owner];
}

async function acquireClaim(pool, key, companyId, source, ttlMs, ownerId) {
    await pool.query(
        `INSERT INTO StackCTRLIntelligenceScheduleRuns
         (CompanyID, ScheduleKey, RunType, TriggerType, DeduplicationKey, Status, CollectionSummaryJson)
         VALUES (?, ?, ?, 'internal', ?, 'claimed', JSON_OBJECT('owner', ?, 'expiresAt', ${dbTime} + ?))
         ON DUPLICATE KEY UPDATE CollectionSummaryJson =
            IF(RunType = ? AND ${expiry} <= ${dbTime}, VALUES(CollectionSummaryJson), CollectionSummaryJson)`,
        [companyId, source, kind, key, ownerId, ttlMs, kind]
    );
    const claim = { key, owner: ownerId, companyId: Number(companyId) };
    const [rows] = await pool.query(
        `SELECT ID FROM StackCTRLIntelligenceScheduleRuns
         WHERE DeduplicationKey = ? AND RunType = ? AND ${owner} = ? AND ${expiry} > ${dbTime}`,
        validClaim(claim)
    );
    return rows.length ? claim : null;
}

async function renewClaim(pool, claim, ttlMs) {
    const [result] = await pool.query(
        `UPDATE StackCTRLIntelligenceScheduleRuns SET CollectionSummaryJson =
            JSON_SET(CollectionSummaryJson, '$.expiresAt', ${dbTime} + ?)
         WHERE DeduplicationKey = ? AND RunType = ? AND ${owner} = ? AND ${expiry} > ${dbTime}`,
        [ttlMs, ...validClaim(claim)]
    );
    return result.affectedRows === 1;
}

async function releaseClaim(pool, claim) {
    await pool.query(
        `UPDATE StackCTRLIntelligenceScheduleRuns SET CollectionSummaryJson =
            JSON_SET(CollectionSummaryJson, '$.expiresAt', 0)
         WHERE DeduplicationKey = ? AND RunType = ? AND ${owner} = ?`,
        validClaim(claim)
    );
}

async function runWithCollectionOwnership(pool, { companyId, tenantId, source, signal, maxMs = 180000, ttlMs = 60000, logger = console, onOwnershipLost }, collect) {
    signal?.throwIfAborted();
    const claim = await acquireClaim(pool, claimKey(companyId, tenantId, source), companyId, source, ttlMs, randomUUID());
    if (!claim) return { companyId, source, status: 'already_running' };
    const deadline = performance.now() + maxMs;
    const realClaim = { ...claim, signal, deadline };
    let renewal;
    const timer = setInterval(() => {
        if (renewal || signal?.aborted || performance.now() >= deadline) return;
        renewal = renewClaim(pool, claim, ttlMs).then(renewed => {
            if (!renewed) onOwnershipLost?.(collectionOwnershipError());
        }).catch(error => {
            logger.warn('[Graph Collection Ownership] Renewal failed:', error.message);
        }).finally(() => { renewal = null; });
    }, Math.max(1000, Math.floor(ttlMs / 3)));
    timer.unref();
    try {
        signal?.throwIfAborted();
        return await ownership.run(realClaim, collect);
    } finally {
        clearInterval(timer);
        // The owner predicate makes an already queued renewal harmless.
        await releaseClaim(pool, claim).catch(error => logger.warn('[Graph Collection Ownership] Release failed:', error.message));
    }
}

function collectionOwnershipError() {
    return Object.assign(new Error('Graph collection ownership expired before publication'), { code: 'GRAPH_COLLECTION_OWNERSHIP_LOST' });
}

async function assertCollectionOwner(connection, companyId) {
    const claim = ownership.getStore();
    if (!claim) return;
    claim.signal?.throwIfAborted();
    if (claim.companyId === Number(companyId) && performance.now() < claim.deadline) {
        const [rows] = await connection.query(
            `SELECT ID FROM StackCTRLIntelligenceScheduleRuns WHERE DeduplicationKey = ?
             AND RunType = ? AND ${owner} = ? AND ${expiry} > ${dbTime} FOR UPDATE`,
            validClaim(claim)
        );
        if (rows.length) return;
    }
    throw collectionOwnershipError();
}

async function withCollectionPublication(database, companyId, write, { transaction = false } = {}) {
    if (!transaction && !ownership.getStore()) return write(database);
    const connection = typeof database.getConnection === 'function' ? await database.getConnection() : database;
    try {
        await connection.beginTransaction();
        await assertCollectionOwner(connection, companyId);
        const result = await write(connection);
        await assertCollectionOwner(connection, companyId);
        await connection.commit();
        return result;
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        if (connection !== database) connection.release();
    }
}

module.exports = { acquireClaim, claimKey, renewClaim, releaseClaim, runWithCollectionOwnership, assertCollectionOwner, withCollectionPublication };
