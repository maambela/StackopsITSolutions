const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { types } = require('node:util');

const requests = new AsyncLocalStorage();
const failureCodes = new WeakMap();
const diagnosedErrors = new WeakSet();
const maxFramePayload = 0xffffff;
const packetLimitSql = `SELECT CONNECTION_ID() AS connectionId,
    @@session.max_allowed_packet AS sessionMaxAllowedPacket,
    @@global.max_allowed_packet AS globalMaxAllowedPacket`;
const lostConnectionCodes = new Set([
    'ECONNRESET', 'ECONNABORTED', 'ECANCELED', 'EPIPE', 'ETIMEDOUT',
    'PROTOCOL_CONNECTION_LOST', 'PROTOCOL_ENQUEUE_AFTER_FATAL_ERROR',
    'ER_NET_PACKET_TOO_LARGE', 'ER_SERVER_SHUTDOWN', 'CR_SERVER_GONE_ERROR', 'CR_SERVER_LOST'
]);

function withSnapshotSqlRequest(work) {
    const active = requests.getStore();
    if (active) return work(active);
    const requestId = randomUUID();
    return requests.run(requestId, work, requestId);
}

function connectionUnusable(connection, error) {
    const raw = connection?.connection ?? connection;
    return Boolean(raw?.stream?.destroyed || raw?._fatalError || raw?._closing ||
        error?.fatal || lostConnectionCodes.has(error?.code) || [1053, 1153, 2006, 2013].includes(error?.errno));
}

function markSnapshotFailure(error, code) {
    if (error && typeof error === 'object') failureCodes.set(error, code);
}

function snapshotFailureCode(error) {
    if (failureCodes.has(error)) return failureCodes.get(error);
    if (error?.code === 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE' || error?.code === 'ER_NET_PACKET_TOO_LARGE' || error?.errno === 1153)
        return 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE';
    return connectionUnusable(null, error) ? 'SNAPSHOT_DATABASE_UNAVAILABLE' : 'SNAPSHOT_CREATION_FAILED';
}

function emit(logger, level, event, details) {
    try {
        logger[level]?.(JSON.stringify({ severity: level === 'error' ? 'ERROR' : level === 'warn' ? 'WARNING' : 'INFO', event, ...details }));
    } catch {
        // Diagnostic output must not change the result of a database operation.
    }
}

function errorFields(error) {
    return {
        errorCode: typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : null,
        mysqlErrno: Number.isSafeInteger(error?.errno) ? error.errno : null
    };
}

function sqlPayloadErrorMessage(error) {
    return diagnosedErrors.has(error)
        ? (errorFields(error).errorCode || 'Snapshot SQL operation failed.')
        : error?.message;
}

function countEscapes(value) {
    let count = 0;
    for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code === 0 || code === 8 || code === 9 || code === 10 || code === 13 ||
            code === 26 || code === 34 || code === 39 || code === 92) count++;
    }
    return count;
}

// Only the default mysql2 UTF-8 text query formatter is eligible for exact preflight.
// Use the borrowed connection's formatter for the SQL skeleton and non-string values.
// Each normal string placeholder adds its UTF-8 bytes plus one byte per sqlstring escape.
function usesDefaultUtf8(connection) {
    const raw = connection?.connection ?? connection;
    return typeof connection?.format === 'function' &&
        (raw?.clientEncoding === 'utf8' || raw?.clientEncoding === 'utf8mb4') && raw.config &&
        !raw.config.queryFormat && !raw.config.namedPlaceholders;
}

function isScalar(value) {
    const type = typeof value;
    return value == null || type === 'string' || type === 'number' || type === 'boolean' || types.isDate(value);
}

function measureQuery(connection, sql, values, columns) {
    const defaultUtf8 = usesDefaultUtf8(connection) && Array.isArray(values) && !sql.includes('??') &&
        (sql.match(/\?/g) || []).length === values.length && values.every(isScalar);
    if (!defaultUtf8) {
        return { measurement: 'unavailable', columns: collectColumns(columns, values), commandBytes: null, protocolHeaderBytes: null, wireBytes: null };
    }

    const stringBytes = new Map();
    const skeleton = values.map((value, index) => {
        if (typeof value !== 'string') return value;
        const utf8Bytes = Buffer.byteLength(value, 'utf8');
        stringBytes.set(index, { utf8Bytes, escapedBytes: utf8Bytes + countEscapes(value) + 2 });
        return '';
    });
    let commandBytes = 1 + Buffer.byteLength(connection.format(sql, skeleton), 'utf8');
    for (const { escapedBytes } of stringBytes.values()) commandBytes += escapedBytes - 2;
    const protocolHeaderBytes = 4 * (Math.floor(commandBytes / maxFramePayload) + 1);
    return {
        measurement: 'mysql2_utf8_com_query_exact',
        columns: collectColumns(columns, values, stringBytes),
        commandBytes, protocolHeaderBytes, wireBytes: commandBytes + protocolHeaderBytes
    };
}

// The hot path for normal child rows only needs a conservative bound. Escape
// counting and formatting are deferred until the bound is near the warning
// threshold or MySQL returns an error.
function wellBelowLimit(sql, values, limit) {
    let upperBound = 1 + 3 * sql.length;
    for (const value of values) {
        if (!isScalar(value)) return false;
        upperBound += typeof value === 'string' ? 4 * value.length + 2 : 40;
    }
    return upperBound < limit * 0.8;
}

function collectColumns(columns, values, stringBytes = null) {
    return Object.fromEntries(Object.entries(columns).map(([column, indexes]) => {
        let utf8Bytes = 0;
        let escapedBytes = 0;
        for (const index of [].concat(indexes)) {
            const value = values[index];
            const sizes = stringBytes?.get(index);
            if (typeof value === 'string') utf8Bytes += sizes?.utf8Bytes ?? Buffer.byteLength(value, 'utf8');
            escapedBytes += sizes?.escapedBytes ?? (value == null ? 4 : 0);
        }
        return [column, { utf8Bytes, escapedBytes: stringBytes ? escapedBytes : null }];
    }));
}

function sourceEvidenceCounts(sources = []) {
    return Object.fromEntries(sources.map(source => [
        source.sourceKey,
        Number.isSafeInteger(source.sourceLineage?.evidenceRecordCount)
            ? source.sourceLineage.evidenceRecordCount : (source.evidence?.length ?? 0)
    ]));
}

function createSqlPayloadDiagnostics(connection, { companyId, logger = console, evidenceCounts = {}, table } = {}) {
    const base = { companyId: Number(companyId), requestId: requests.getStore() || randomUUID(), evidenceCounts, table };
    const metadata = {
        connectionId: connection.threadId ?? null,
        sessionMaxAllowedPacket: null,
        globalMaxAllowedPacket: null
    };
    let metadataRead = false;
    let metadataErrorCode = null;
    async function packetLimits() {
        metadataRead = true;
        if (typeof connection.format !== 'function') return;
        try {
            const [[row]] = await connection.query(packetLimitSql);
            for (const key of Object.keys(metadata)) {
                const value = Number(row?.[key]);
                if (Number.isSafeInteger(value) && value > 0) metadata[key] = value;
            }
        } catch (error) {
            metadataErrorCode = errorFields(error).errorCode;
            if (connectionUnusable(connection, error)) throw error;
        }
    }
    function failure(event, operation, error, details = {}) {
        if (event === 'snapshot_sql_execution_failed' && error && typeof error === 'object') diagnosedErrors.add(error);
        emit(logger, 'error', event, { ...base, ...metadata, operation, ...details, ...errorFields(error) });
    }
    function describe(operation, sql, values, columns) {
        const size = measureQuery(connection, sql, values, columns);
        const limit = metadata.sessionMaxAllowedPacket;
        const comparable = limit != null && size.commandBytes != null;
        return {
            ...base, ...metadata, operation, ...size,
            headroomBytes: comparable ? limit - size.commandBytes : null,
            packetLimitPercent: comparable ? Number((100 * size.commandBytes / limit).toFixed(2)) : null,
            metadataErrorCode
        };
    }
    async function query(operation, sql, values, { columns = {}, quiet = false, signal } = {}) {
        let details;
        let stage = 'metadata';
        try {
            if (!metadataRead) await packetLimits();
            const limit = metadata.sessionMaxAllowedPacket;
            stage = 'measurement';
            if (!(quiet && limit != null && usesDefaultUtf8(connection) && wellBelowLimit(sql, values, limit))) {
                details = describe(operation, sql, values, columns);
                if (!quiet) emit(logger, 'info', 'snapshot_sql_payload_measured', details);
                // MySQL's receive-buffer limit also rejects an exact-limit request.
                if (details.headroomBytes != null && details.headroomBytes <= 0) {
                    const code = 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE';
                    emit(logger, 'error', 'snapshot_sql_payload_exceeds_limit', { ...details, errorCode: code });
                    throw Object.assign(new Error('Snapshot data exceeds the database packet limit.'), { code });
                }
                if (details.packetLimitPercent >= 80) emit(logger, 'warn', 'snapshot_sql_payload_warning', details);
            }
            stage = 'execution';
            signal?.throwIfAborted();
            return await connection.query(sql, values);
        } catch (error) {
            if (error?.code !== 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE') {
                if (!details && stage === 'execution') {
                    try { details = describe(operation, sql, values, columns); } catch { /* Preserve the execution error. */ }
                }
                failure('snapshot_sql_execution_failed', operation, error, { ...details, stage });
            }
            throw error;
        }
    }
    return { query, failure };
}

async function onSqlPayloadConnection(database, work) {
    if (typeof database.getConnection !== 'function') return work(database);
    const connection = await database.getConnection();
    let reusable = true;
    try {
        return await work(connection);
    } catch (error) {
        reusable = !connectionUnusable(connection, error);
        throw error;
    } finally {
        if (reusable) connection.release();
        else connection.destroy();
    }
}

module.exports = {
    connectionUnusable, createSqlPayloadDiagnostics, markSnapshotFailure, measureQuery,
    onSqlPayloadConnection, snapshotFailureCode, sourceEvidenceCounts, sqlPayloadErrorMessage, withSnapshotSqlRequest
};
