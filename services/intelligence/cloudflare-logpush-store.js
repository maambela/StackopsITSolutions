const crypto = require('crypto');
const { normaliseCloudflareLogpushPayload } = require('./cloudflare-logpush');
const { SECURITY_ALERT_STORAGE_ENABLED } = require('./security-storage-policy');

const SCHEMA = [
    `CREATE TABLE IF NOT EXISTS StackCTRLCloudflareTenantMappings (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        CompanyID BIGINT NOT NULL,
        CloudflareAccountID VARCHAR(100) NOT NULL,
        LogpushSecretSha256 CHAR(64) NOT NULL,
        IsEnabled TINYINT(1) NOT NULL DEFAULT 1,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_cloudflare_tenant_account (CloudflareAccountID),
        KEY ix_cloudflare_tenant_company (CompanyID, IsEnabled)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    `CREATE TABLE IF NOT EXISTS StackCTRLCloudflareLogpushEvents (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        CompanyID BIGINT NOT NULL,
        CloudflareAccountID VARCHAR(100) NOT NULL,
        Dataset VARCHAR(64) NOT NULL,
        EventKey VARCHAR(255) NOT NULL,
        EventTime DATETIME(3) NULL,
        ReceivedAt DATETIME(3) NOT NULL,
        ProcessedEventJson JSON NOT NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_cloudflare_logpush_event (CompanyID, CloudflareAccountID, Dataset, EventKey),
        KEY ix_cloudflare_logpush_company_time (CompanyID, ReceivedAt),
        KEY ix_cloudflare_logpush_dataset_time (CompanyID, Dataset, EventTime)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
];

function hashSecret(value) {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function safeEqual(left, right) {
    const a = Buffer.from(String(left || ''));
    const b = Buffer.from(String(right || ''));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function mysqlDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 23).replace('T', ' ');
}

function createCloudflareLogpushStore({ pool, now = () => new Date(), onRecords = () => {}, persistenceEnabled = SECURITY_ALERT_STORAGE_ENABLED } = {}) {
    if (!pool?.query) throw new Error('Cloudflare Logpush storage requires a database pool');
    return {
        async ensureSchema() {
            if (!persistenceEnabled) return { storageMode: 'memory_only' };
            for (const statement of SCHEMA) await pool.query(statement);
        },
        async authenticate({ accountId, secret }) {
            const normalizedAccountId = String(accountId || '').trim();
            if (!normalizedAccountId || !secret) return null;
            const [rows] = await pool.query(
                `SELECT CompanyID, CloudflareAccountID, LogpushSecretSha256
                 FROM StackCTRLCloudflareTenantMappings
                 WHERE CloudflareAccountID = ? AND IsEnabled = 1 LIMIT 1`,
                [normalizedAccountId]
            );
            const mapping = rows?.[0];
            if (!mapping || !safeEqual(mapping.LogpushSecretSha256, hashSecret(secret))) return null;
            const companyId = Number(mapping.CompanyID);
            if (!Number.isInteger(companyId) || companyId <= 0) return null;
            return { companyId, accountId: mapping.CloudflareAccountID };
        },
        async ingest({ companyId, accountId, dataset, payload }) {
            const records = normaliseCloudflareLogpushPayload(payload, { dataset, accountId });
            onRecords({ companyId, accountId, dataset, records });
            if (!persistenceEnabled) return { received: records.length, inserted: 0, duplicates: 0, stored: false, storageMode: 'memory_only' };
            let inserted = 0;
            for (const record of records) {
                const [result] = await pool.query(
                    `INSERT IGNORE INTO StackCTRLCloudflareLogpushEvents
                     (CompanyID, CloudflareAccountID, Dataset, EventKey, EventTime, ReceivedAt, ProcessedEventJson)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [companyId, accountId, record.dataset, record.eventKey, mysqlDate(record.eventTime), mysqlDate(now()), JSON.stringify(record)]
                );
                inserted += Number(result?.affectedRows || 0);
            }
            return { received: records.length, inserted, duplicates: records.length - inserted };
        },
        async recentEvents(companyId, { days = Number(process.env.SECURITY_EVIDENCE_HISTORY_DAYS) || 15 } = {}) {
            if (!persistenceEnabled) return [];
            const records = []; let after = 0;
            while (true) {
                const [rows] = await pool.query(
                    `SELECT ID, ProcessedEventJson FROM StackCTRLCloudflareLogpushEvents
                     WHERE CompanyID = ? AND ID > ? AND ReceivedAt >= DATE_SUB(NOW(), INTERVAL ? DAY)
                     ORDER BY ID LIMIT 500`, [companyId, after, days]);
                if (!rows.length) break;
                for (const row of rows) records.push(typeof row.ProcessedEventJson === 'string' ? JSON.parse(row.ProcessedEventJson) : row.ProcessedEventJson);
                after = rows[rows.length - 1].ID;
            }
            return records;
        }
    };
}

module.exports = { createCloudflareLogpushStore, hashSecret };
