const assert = require('node:assert/strict');
const test = require('node:test');
const { createWhatsAppNotificationLedger } = require('../services/whatsapp-notification-ledger');

function createFakePool({ tableExists = false, createError = null, createDelayMs = 0 } = {}) {
  const rows = new Map();
  const queries = [];
  let createCount = 0;
  let currentCreateError = createError;
  let selectedDatabase = 'consultation_db';
  let tableCreated = tableExists;

  return {
    rows,
    queries,
    get createCount() { return createCount; },
    setCreateError(error) { currentCreateError = error; },
    async query(sql, params = []) {
      queries.push(sql);
      if (sql.includes('CREATE TABLE IF NOT EXISTS WhatsAppSecurityAlertNotifications')) {
        createCount += 1;
        if (createDelayMs) await new Promise(resolve => setTimeout(resolve, createDelayMs));
        if (currentCreateError) throw currentCreateError;
        tableCreated = true;
        return [{ affectedRows: 0 }];
      }
      if (sql.includes('SELECT DATABASE()')) return [[{ databaseName: selectedDatabase }]];
      if (sql.includes('information_schema.tables')) return [[{ tableExists: tableCreated ? 1 : 0 }]];
      if (sql.includes('INSERT IGNORE INTO WhatsAppSecurityAlertNotifications')) {
        const [key, recipient, alertType, severity, issue] = params;
        if (rows.has(key)) return [{ affectedRows: 0 }];
        rows.set(key, {
          NotificationKey: key,
          Recipient: recipient,
          AlertType: alertType,
          Severity: severity,
          Issue: issue,
          Status: 'pending',
          MetaMessageID: null,
          ErrorMessage: null,
          CreatedAt: new Date()
        });
        return [{ affectedRows: 1 }];
      }
      if (sql.includes('SELECT Status, MetaMessageID, CreatedAt')) {
        const row = rows.get(params[0]);
        return [row ? [{ Status: row.Status, MetaMessageID: row.MetaMessageID, CreatedAt: row.CreatedAt }] : []];
      }
      if (sql.includes('UPDATE WhatsAppSecurityAlertNotifications')) {
        const [status, messageId, errorMessage, _sentStatus, key] = params;
        const row = rows.get(key);
        if (row) Object.assign(row, { Status: status, MetaMessageID: messageId, ErrorMessage: errorMessage });
        return [{ affectedRows: row ? 1 : 0 }];
      }
      throw new Error(`Unexpected SQL in test pool: ${sql}`);
    }
  };
}

function createLedger(pool, logger = { info() {}, error() {} }) {
  return createWhatsAppNotificationLedger({
    pool,
    buildKey: alert => `key:${alert.id}`,
    normalizeSeverity: value => String(value || 'medium').toLowerCase(),
    logger
  });
}

test('cold-start initialization creates the table and verifies consultation_db', async () => {
  const pool = createFakePool();
  const logs = [];
  const ledger = createLedger(pool, { info: (...args) => logs.push(args), error() {} });

  const result = await ledger.ensureWhatsAppSecurityAlertTable();

  assert.equal(result.databaseName, 'consultation_db');
  assert.equal(result.tableExists, true);
  assert.equal(pool.createCount, 1);
  assert.ok(logs.some(([label, details]) =>
    label === '[WhatsApp DB Check]' && details.database === 'consultation_db' && details.tableExists
  ));
});

test('existing table is safe and schema creation is shared by simultaneous operations', async () => {
  const pool = createFakePool({ tableExists: true, createDelayMs: 20 });
  const ledger = createLedger(pool);
  const alert = { id: 'parallel-1', severity: 'high', issue: 'Concurrent alert' };

  const claims = await Promise.all([
    ledger.claimWhatsAppSecurityAlertNotification(alert, '27762609804'),
    ledger.claimWhatsAppSecurityAlertNotification(alert, '27762609804'),
    ledger.ensureWhatsAppSecurityAlertTable()
  ]);

  assert.equal(pool.createCount, 1);
  assert.equal(claims.filter(claim => claim.claimed).length, 1);
  assert.equal(claims.filter(claim => claim.claimed === false).length, 1);
  assert.equal(pool.rows.size, 1);
});

test('duplicate notification key reads the prior status and preserves its Meta message ID', async () => {
  const pool = createFakePool();
  const ledger = createLedger(pool);
  const alert = { id: 'duplicate-1', severity: 'critical', issue: 'Repeated alert' };

  const firstClaim = await ledger.claimWhatsAppSecurityAlertNotification(alert, '27762609804');
  await ledger.completeWhatsAppSecurityAlertNotification(firstClaim.notificationKey, {
    status: 'sent',
    messageId: 'wamid.persisted'
  });
  const duplicateClaim = await ledger.claimWhatsAppSecurityAlertNotification(alert, '27762609804');

  assert.equal(firstClaim.claimed, true);
  assert.equal(duplicateClaim.claimed, false);
  assert.equal(duplicateClaim.status, 'sent');
  assert.equal(duplicateClaim.messageId, 'wamid.persisted');
  assert.equal(pool.rows.size, 1);
});

test('successful and failed sends persist status, message ID, and error detail', async () => {
  const pool = createFakePool();
  const ledger = createLedger(pool);
  const sentClaim = await ledger.claimWhatsAppSecurityAlertNotification({ id: 'sent-1', issue: 'Sent' }, '27762609804');
  const failedClaim = await ledger.claimWhatsAppSecurityAlertNotification({ id: 'failed-1', issue: 'Failed' }, '27762609804');

  await ledger.completeWhatsAppSecurityAlertNotification(sentClaim.notificationKey, {
    status: 'sent',
    messageId: 'wamid.sent'
  });
  await ledger.completeWhatsAppSecurityAlertNotification(failedClaim.notificationKey, {
    status: 'failed',
    error: 'Meta rejected the message'
  });

  assert.equal(pool.rows.get(sentClaim.notificationKey).Status, 'sent');
  assert.equal(pool.rows.get(sentClaim.notificationKey).MetaMessageID, 'wamid.sent');
  assert.equal(pool.rows.get(failedClaim.notificationKey).Status, 'failed');
  assert.equal(pool.rows.get(failedClaim.notificationKey).ErrorMessage, 'Meta rejected the message');
});

test('table initialization logs the full database error and retries after failure', async () => {
  const failure = Object.assign(new Error('access denied creating table'), { code: 'ER_TABLEACCESS_DENIED_ERROR' });
  const pool = createFakePool({ createError: failure });
  const loggedErrors = [];
  const ledger = createLedger(pool, {
    info() {},
    error: (...args) => loggedErrors.push(args)
  });

  await assert.rejects(ledger.ensureWhatsAppSecurityAlertTable(), error => error === failure);
  assert.equal(loggedErrors[0][0], '[WhatsApp Security] Table initialization failed:');
  assert.equal(loggedErrors[0][1], failure);

  pool.setCreateError(null);
  const result = await ledger.ensureWhatsAppSecurityAlertTable();
  assert.equal(result.tableExists, true);
  assert.equal(pool.createCount, 2);
});
