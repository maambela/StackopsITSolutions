CREATE TABLE IF NOT EXISTS StackCTRL1PasswordEventSyncState (
    CompanyID BIGINT NOT NULL,
    EventType VARCHAR(32) NOT NULL,
    LastProcessedCursor TEXT NULL,
    LastSuccessfulSyncAt DATETIME(3) NULL,
    SyncStatus VARCHAR(20) NOT NULL DEFAULT 'idle',
    LastError VARCHAR(255) NULL,
    UpdatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (CompanyID, EventType),
    KEY ix_stackctrl_1password_sync_status (SyncStatus, UpdatedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRL1PasswordEventMetadata (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    EventType VARCHAR(32) NOT NULL,
    EventUUID VARCHAR(100) NOT NULL,
    EventTimestamp DATETIME(3) NULL,
    MetadataJson JSON NOT NULL,
    IngestedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (ID),
    UNIQUE KEY uq_stackctrl_1password_event (CompanyID, EventType, EventUUID),
    KEY ix_stackctrl_1password_timeline (CompanyID, EventTimestamp, ID),
    KEY ix_stackctrl_1password_event_type (CompanyID, EventType, EventTimestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
