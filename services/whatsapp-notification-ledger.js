const WHATSAPP_SECURITY_ALERT_TABLE = `
    CREATE TABLE IF NOT EXISTS WhatsAppSecurityAlertNotifications (
        ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        NotificationKey VARCHAR(100) NOT NULL,
        Recipient VARCHAR(32) NOT NULL,
        AlertType VARCHAR(32) NOT NULL,
        Severity VARCHAR(16) NOT NULL,
        Issue VARCHAR(900) NOT NULL,
        Status VARCHAR(32) NOT NULL DEFAULT 'pending',
        MetaMessageID VARCHAR(255) NULL,
        ErrorMessage TEXT NULL,
        SentAt DATETIME NULL,
        CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (ID),
        UNIQUE KEY uq_whatsapp_security_notification (NotificationKey),
        KEY ix_whatsapp_security_notification_status (Status, CreatedAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
`;

function createWhatsAppNotificationLedger({ pool, buildKey, normalizeSeverity, logger = console }) {
    let initializationPromise = null;

    function ensureWhatsAppSecurityAlertTable() {
        if (!pool) return Promise.reject(new Error('MySQL pool is not available for the WhatsApp notification ledger.'));

        if (!initializationPromise) {
            initializationPromise = (async () => {
                await pool.query(WHATSAPP_SECURITY_ALERT_TABLE);
                const [databaseRows] = await pool.query('SELECT DATABASE() AS databaseName');
                const [tableRows] = await pool.query(`
                    SELECT COUNT(*) AS tableExists
                    FROM information_schema.tables
                    WHERE table_schema = DATABASE()
                      AND table_name = 'WhatsAppSecurityAlertNotifications'
                `);
                const databaseName = databaseRows[0]?.databaseName || null;
                const tableExists = Number(tableRows[0]?.tableExists) === 1;

                logger.info('[WhatsApp DB Check]', {
                    database: databaseName,
                    configuredDatabase: process.env.DB_NAME || null,
                    tableExists
                });

                if (!tableExists) {
                    throw new Error(`WhatsApp notification table was not found in database ${databaseName || '(unknown)'}.`);
                }

                return { databaseName, tableExists };
            })().catch(error => {
                initializationPromise = null;
                logger.error('[WhatsApp Security] Table initialization failed:', error);
                throw error;
            });
        }

        return initializationPromise;
    }

    async function claimWhatsAppSecurityAlertNotification(alert, recipient) {
        if (!pool) {
            return { claimed: false, status: 'skipped-ledger-unavailable' };
        }

        await ensureWhatsAppSecurityAlertTable();
        const notificationKey = buildKey(alert, recipient);
        const [insert] = await pool.query(
            `INSERT IGNORE INTO WhatsAppSecurityAlertNotifications
             (NotificationKey, Recipient, AlertType, Severity, Issue, Status)
             VALUES (?, ?, ?, ?, ?, 'pending')`,
            [
                notificationKey,
                recipient,
                String(alert.recordType || alert.type || 'security').slice(0, 32),
                normalizeSeverity(alert.severity),
                String(alert.issue || alert.title || alert.displayName || alert.name || 'Security alert').slice(0, 900)
            ]
        );

        if (insert.affectedRows === 1) return { claimed: true, notificationKey };

        const [rows] = await pool.query(
            'SELECT Status, MetaMessageID, CreatedAt FROM WhatsAppSecurityAlertNotifications WHERE NotificationKey = ? LIMIT 1',
            [notificationKey]
        );
        return {
            claimed: false,
            notificationKey,
            status: rows[0]?.Status || 'existing',
            messageId: rows[0]?.MetaMessageID || null,
            createdAt: rows[0]?.CreatedAt || null
        };
    }

    async function completeWhatsAppSecurityAlertNotification(notificationKey, result = {}) {
        if (!pool || !notificationKey) return;

        await ensureWhatsAppSecurityAlertTable();
        await pool.query(
            `UPDATE WhatsAppSecurityAlertNotifications
             SET Status = ?, MetaMessageID = ?, ErrorMessage = ?, SentAt = CASE WHEN ? = 'sent' THEN NOW() ELSE SentAt END
             WHERE NotificationKey = ?`,
            [
                result.status || 'failed',
                result.messageId || null,
                result.error ? String(result.error).slice(0, 4000) : null,
                result.status || 'failed',
                notificationKey
            ]
        );
    }

    return {
        ensureWhatsAppSecurityAlertTable,
        claimWhatsAppSecurityAlertNotification,
        completeWhatsAppSecurityAlertNotification
    };
}

module.exports = {
    createWhatsAppNotificationLedger
};
