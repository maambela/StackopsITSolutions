const assert = require('node:assert/strict');
const test = require('node:test');
const mysql = require('mysql2');
const { createStackCTRLIntelligenceService } = require('../services/stackctrl-intelligence');
const {
    createSqlPayloadDiagnostics, measureQuery, snapshotFailureCode, withSnapshotSqlRequest
} = require('../services/intelligence/sql-payload-diagnostics');

function capture() {
    const events = [];
    const log = message => events.push(JSON.parse(message));
    return { events, logger: { info: log, warn: log, error: log } };
}

test('payload guard measures exact escaping, warns, and reuses one packet limit lookup', async () => {
    const { events, logger } = capture();
    const calls = [];
    const connection = {
        connection: { clientEncoding: 'utf8', config: {} },
        format: mysql.format,
        async query(sql, params) {
            calls.push(sql);
            if (!params) return [[{ connectionId: 91, sessionMaxAllowedPacket: 120, globalMaxAllowedPacket: 128 }]];
            return [{}];
        }
    };
    const sql = 'UPDATE Fixture SET Payload = ? WHERE ID = ?';
    const payload = JSON.stringify({ secret: 'café 😀 日 " \\\n\u0000' });
    await withSnapshotSqlRequest(async requestId => {
        const diagnostic = createSqlPayloadDiagnostics(connection, { companyId: 1, logger, evidenceCounts: { identity: 3 } });
        const columns = { Payload: 0 };
        await diagnostic.query('fixture_update', sql, [payload, 1], { columns });
        await assert.rejects(diagnostic.query('fixture_update', sql, [payload.repeat(3), 1], { columns }),
            { code: 'SNAPSHOT_SQL_PAYLOAD_TOO_LARGE' });
        assert.ok(events.every(event => event.requestId === requestId));
    });
    const size = events[0];
    assert.equal(size.commandBytes, Buffer.byteLength(mysql.format(sql, [payload, 1])) + 1);
    assert.equal(size.columns.Payload.escapedBytes, Buffer.byteLength(mysql.escape(payload)));
    assert.equal(size.columns.Payload.utf8Bytes, Buffer.byteLength(payload));
    assert.deepEqual(calls, [calls[0], sql]);
    assert.match(calls[0], /CONNECTION_ID\(\).*@@session\.max_allowed_packet.*@@global\.max_allowed_packet/s);
    assert.deepEqual(events.map(event => event.event), [
        'snapshot_sql_payload_measured', 'snapshot_sql_payload_warning',
        'snapshot_sql_payload_measured', 'snapshot_sql_payload_exceeds_limit'
    ]);
    assert.doesNotMatch(JSON.stringify(events), /café|Fixture SET|secret/);
    connection.connection.config.queryFormat = () => payload;
    assert.equal(measureQuery(connection, sql, [payload, 1], { Payload: 0 }).measurement, 'unavailable');
});

test('small child writes defer exact formatting until an execution failure', async () => {
    const { events, logger } = capture();
    const original = new Error('private failure detail');
    let formatCalls = 0;
    let fail = false;
    const connection = {
        connection: { clientEncoding: 'utf8', config: {} },
        format(sql, values) { formatCalls++; return mysql.format(sql, values); },
        async query(_sql, values) {
            if (!values) return [[{ sessionMaxAllowedPacket: 33554432 }]];
            if (fail) throw original;
            return [{}];
        }
    };
    const diagnostic = createSqlPayloadDiagnostics(connection, { companyId: 1, logger });
    const sql = 'INSERT INTO Fixture VALUES (?)';
    const options = { quiet: true, columns: { Payload: 0 } };
    const values = [JSON.stringify({ note: 'private café 😀' })];
    await diagnostic.query('child_insert', sql, values, options);
    assert.equal(formatCalls, 0);
    assert.equal(events.length, 0);
    fail = true;
    await assert.rejects(diagnostic.query('child_insert', sql, values, options), error => error === original);
    assert.equal(formatCalls, 1);
    assert.equal(events[0].commandBytes, Buffer.byteLength(mysql.format(sql, values)) + 1);
    assert.doesNotMatch(JSON.stringify(events), /private|café/);
});

function fixture() {
    return { companyId: 1, tenantKey: 'fixture', sources: [], sourceFreshness: {}, metrics: {}, evidence: [], context: {}, dataCompletenessScore: 100 };
}

test('tenant transaction reports rollback failure separately and preserves the primary error object', async () => {
    const { events, logger } = capture();
    const original = Object.assign(new Error('confidential SQL detail'), { code: 'ER_BAD_FIELD_ERROR', sql: 'confidential' });
    const rollback = Object.assign(new Error('confidential rollback detail'), { code: 'ECONNRESET' });
    const calls = [];
    const connection = {
        async beginTransaction() { calls.push('begin'); },
        async query() { calls.push('write'); throw original; },
        async rollback() { calls.push('rollback'); throw rollback; },
        release() { calls.push('release'); },
        destroy() { calls.push('destroy'); }
    };
    const service = createStackCTRLIntelligenceService({ pool: { getConnection: async () => connection }, azureOpenAI: {}, logger });
    await assert.rejects(service.createSnapshotFromBuiltContext({ built: fixture() }), error => error === original);
    assert.deepEqual(calls, ['begin', 'write', 'rollback', 'destroy']);
    assert.equal(events.find(event => event.event === 'snapshot_sql_execution_failed').errorCode, original.code);
    assert.equal(events.find(event => event.event === 'snapshot_transaction_rollback_failed').errorCode, rollback.code);
    assert.doesNotMatch(JSON.stringify(events), /confidential/);
});

test('a lost commit acknowledgement is never retried or classified as a confirmed rollback', async () => {
    const { events, logger } = capture();
    const original = Object.assign(new Error('socket lost'), { code: 'ECONNRESET' });
    const calls = [];
    const connection = {
        async beginTransaction() { calls.push('begin'); },
        async query() { calls.push('write'); return [{ insertId: 1 }]; },
        async commit() { calls.push('commit'); throw original; },
        async rollback() { calls.push('rollback'); },
        release() { calls.push('release'); },
        destroy() { calls.push('destroy'); }
    };
    const service = createStackCTRLIntelligenceService({ pool: { getConnection: async () => connection }, azureOpenAI: {}, logger });
    await assert.rejects(service.createSnapshotFromBuiltContext({ built: fixture() }), error => {
        assert.equal(error, original);
        assert.equal(snapshotFailureCode(error), 'SNAPSHOT_COMMIT_OUTCOME_UNKNOWN');
        return true;
    });
    assert.deepEqual(calls, ['begin', 'write', 'commit', 'destroy']);
    assert.equal(events.find(event => event.operation === 'tenant_snapshot_commit').commitOutcomeUnknown, true);
});
