const { performance } = require('node:perf_hooks');

const markerKey = '$stackctrlSnapshotStorage';
const columnsByField = { evidence: 'EvidenceJson', metrics: 'MetricsJson' };
const markerPath = `$."${markerKey}"`;
const markerPresentSql = `JSON_CONTAINS_PATH(ContextJson, 'one', '${markerPath}')`;
const canonicalEvidenceSql = `IF(${markerPresentSql}, EvidenceJson, NULL) AS EvidenceJson`;
const fieldSizeSql = (field, column, type) => `IF(JSON_CONTAINS(JSON_EXTRACT(ContextJson, '${markerPath}.fields'), '"${field}"'),
                        IF(JSON_TYPE(${column}) = '${type}', ${Buffer.byteLength(JSON.stringify(field)) + 4} + OCTET_LENGTH(${column}), NULL), 0)`;
// MySQL JSON text renders each member as a quoted key, colon-space, and value.
// Counting one comma-space per member cancels the missing comma on the final member.
const logicalContextBytesSql = `CASE
                    WHEN NOT ${markerPresentSql} THEN OCTET_LENGTH(ContextJson)
                    WHEN JSON_EXTRACT(ContextJson, '${markerPath}.version') = CAST('1' AS JSON)
                        AND JSON_TYPE(JSON_EXTRACT(ContextJson, '${markerPath}.fields')) = 'ARRAY'
                        AND JSON_LENGTH(ContextJson, '${markerPath}.fields') BETWEEN 1 AND 2
                    THEN OCTET_LENGTH(ContextJson) - OCTET_LENGTH(JSON_EXTRACT(ContextJson, '${markerPath}'))
                        - ${Buffer.byteLength(JSON.stringify(markerKey)) + 4}
                        + ${fieldSizeSql('evidence', 'EvidenceJson', 'ARRAY')}
                        + ${fieldSizeSql('metrics', 'MetricsJson', 'OBJECT')}
                END`;

const reported = new Set();

function parsed(value) {
    if (typeof value !== 'string') return value;
    try {
        return JSON.parse(value);
    } catch {
        return undefined;
    }
}

function object(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function invalid(logger, code, message) {
    if (logger?.warn && !reported.has(code)) {
        reported.add(code);
        logger.warn({ event: 'tenant_snapshot_storage_invalid', code });
    }
    throw Object.assign(new Error(message), { code });
}

function compareNativeJsonKeys(left, right) {
    // MySQL binary JSON sorts object keys by UTF-8 byte length, then byte value.
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length - b.length || a.compare(b);
}

function hydrateTenantSnapshot(row, { companyId, tenantKey, logger, nativeJsonOrder = true } = {}) {
    const expected = Number(companyId);
    if (!Number.isSafeInteger(expected) || expected < 1 || Number(row?.CompanyID) !== expected ||
        (tenantKey !== undefined && row.TenantKey !== tenantKey)) {
        invalid(logger, 'TENANT_SNAPSHOT_SCOPE_MISMATCH', 'Snapshot scope mismatch');
    }

    const start = performance.now();
    const context = parsed(row.ContextJson);
    if (!object(context) || !Object.hasOwn(context, markerKey)) return row;

    // This top-level name is reserved by the storage format. The legacy writer
    // constructs its top-level fields explicitly and never emits this key.
    const marker = context[markerKey];
    if (!object(marker) || !Number.isSafeInteger(marker.version) || marker.version < 1) {
        invalid(logger, 'TENANT_SNAPSHOT_INVALID_MARKER', 'Invalid snapshot storage marker');
    }
    if (marker.version !== 1) {
        invalid(logger, 'TENANT_SNAPSHOT_UNSUPPORTED_VERSION', 'Unsupported snapshot storage version');
    }
    const { fields, order } = marker;
    if (Object.keys(marker).length !== 3 ||
        !Array.isArray(fields) || !fields.length || new Set(fields).size !== fields.length ||
        !fields.every(field => typeof field === 'string' && Object.hasOwn(columnsByField, field) && !Object.hasOwn(context, field)) ||
        !Array.isArray(order) || new Set(order).size !== order.length ||
        order.length !== Object.keys(context).length - 1 + fields.length ||
        !order.every(key => typeof key === 'string' && key !== markerKey && (Object.hasOwn(context, key) || fields.includes(key)))) {
        invalid(logger, 'TENANT_SNAPSHOT_INVALID_MARKER', 'Invalid snapshot storage marker');
    }
    if (typeof row.TenantKey !== 'string' || !row.TenantKey ||
        (Object.hasOwn(context, 'tenant') && (!object(context.tenant) ||
            (Object.hasOwn(context.tenant, 'companyId') && Number(context.tenant.companyId) !== expected) ||
            (Object.hasOwn(context.tenant, 'tenantKey') && context.tenant.tenantKey !== row.TenantKey)))) {
        invalid(logger, 'TENANT_SNAPSHOT_SCOPE_MISMATCH', 'Snapshot scope mismatch');
    }

    const restored = new Map();
    for (const field of fields) {
        const value = parsed(row[columnsByField[field]]);
        if (field === 'evidence' ? !Array.isArray(value) : !object(value)) {
            invalid(logger, `TENANT_SNAPSHOT_MISSING_${field.toUpperCase()}`, `Missing canonical ${field}`);
        }
        restored.set(field, value);
    }

    const keys = nativeJsonOrder ? [...order].sort(compareNativeJsonKeys) : order;
    const logicalContext = Object.fromEntries(keys.map(key => [key, restored.has(key) ? restored.get(key) : context[key]]));
    const serialized = typeof row.ContextJson === 'string';
    const result = { ...row, ContextJson: serialized ? JSON.stringify(logicalContext) : logicalContext };
    if (logger?.info && !reported.has(marker.version)) {
        reported.add(marker.version);
        logger.info({
            event: 'tenant_snapshot_hydrated',
            storageVersion: marker.version,
            storedContextBytes: Buffer.byteLength(serialized ? row.ContextJson : JSON.stringify(context)),
            logicalContextBytes: Buffer.byteLength(serialized ? result.ContextJson : JSON.stringify(logicalContext)),
            hydrationMs: Number((performance.now() - start).toFixed(2))
        });
    }
    return result;
}

module.exports = { hydrateTenantSnapshot, canonicalEvidenceSql, logicalContextBytesSql };
