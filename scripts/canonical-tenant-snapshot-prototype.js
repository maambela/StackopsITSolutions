// Local experiment only. The backend does not import this module.
const { isDeepStrictEqual } = require('node:util');

const markerKey = '$stackctrlSnapshotStorage';
const columnsByField = { evidence: 'EvidenceJson', metrics: 'MetricsJson' };

function assertScope(row, { companyId, tenantKey } = {}) {
    const expected = Number(companyId);
    if (!Number.isSafeInteger(expected) || expected < 1 || Number(row?.CompanyID) !== expected ||
        (tenantKey !== undefined && row.TenantKey !== tenantKey)) {
        throw new Error('Snapshot scope mismatch');
    }
}

function parse(value) {
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

function representContext(row, context) {
    return { ...row, ContextJson: typeof row.ContextJson === 'string' ? JSON.stringify(context) : context };
}

function encodeCanonicalSnapshot(row, scope) {
    assertScope(row, scope);
    const context = parse(row.ContextJson);
    if (!object(context)) return row;
    if (Object.hasOwn(context, markerKey)) throw new Error('Reserved snapshot storage marker');
    const fields = Object.entries(columnsByField).filter(([field, column]) => {
        if (!Object.hasOwn(context, field) || row[column] == null) return false;
        const value = parse(row[column]);
        return (field === 'evidence' ? Array.isArray(value) : object(value)) && isDeepStrictEqual(value, context[field]);
    }).map(([field]) => field);
    if (!fields.length) return row;

    const order = Object.keys(context);
    const storedContext = Object.fromEntries(Object.entries(context).filter(([key]) => !fields.includes(key)));
    storedContext[markerKey] = { version: 1, fields, order };
    return representContext(row, storedContext);
}

function decodeCanonicalSnapshot(row, scope) {
    assertScope(row, scope);
    const context = parse(row.ContextJson);
    if (!object(context) || !Object.hasOwn(context, markerKey)) return row;
    const marker = context[markerKey];
    if (marker?.version !== 1) throw new Error('Unsupported snapshot storage version');
    const { fields, order } = marker;
    if (!Array.isArray(fields) || !fields.length || new Set(fields).size !== fields.length ||
        !fields.every(field => Object.hasOwn(columnsByField, field) && !Object.hasOwn(context, field)) ||
        !Array.isArray(order) || new Set(order).size !== order.length ||
        order.length !== Object.keys(context).length - 1 + fields.length ||
        !order.every(key => typeof key === 'string' && key !== markerKey && (Object.hasOwn(context, key) || fields.includes(key)))) {
        throw new Error('Invalid snapshot storage marker');
    }

    const restored = new Map();
    for (const field of fields) {
        const value = parse(row[columnsByField[field]]);
        if (field === 'evidence' ? !Array.isArray(value) : !object(value)) {
            throw new Error(`Missing canonical ${field}`);
        }
        restored.set(field, value);
    }
    return representContext(row, Object.fromEntries(order.map(key => [key, restored.has(key) ? restored.get(key) : context[key]])));
}

module.exports = { encodeCanonicalSnapshot, decodeCanonicalSnapshot };
