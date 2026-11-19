-- StackCTRL Enterprise Intelligence durable storage and normalized Power BI read model.
-- Apply this migration before enabling enterprise schedules.

CREATE TABLE IF NOT EXISTS StackCTRLIdentityEvidenceSnapshots (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    TenantKey VARCHAR(100) NOT NULL,
    CollectionTrigger VARCHAR(50) NOT NULL,
    SourceSystem VARCHAR(100) NOT NULL DEFAULT 'Microsoft Graph via StackCTRL',
    SourceEndpoint VARCHAR(255) NOT NULL,
    CollectionStatus VARCHAR(30) NOT NULL,
    IsComplete TINYINT(1) NOT NULL DEFAULT 0,
    CollectedAt DATETIME(3) NOT NULL,
    SourceFetchedAt DATETIME(3) NULL,
    EvidenceRecordCount INT NOT NULL DEFAULT 0,
    ExpectedRecordCount INT NOT NULL DEFAULT 0,
    OmittedRecordCount INT NOT NULL DEFAULT 0,
    CompletenessPercent DECIMAL(6,2) NOT NULL DEFAULT 0,
    TotalUsers INT NOT NULL DEFAULT 0,
    MFAEnabledUsers INT NOT NULL DEFAULT 0,
    UsersWithoutMFA INT NOT NULL DEFAULT 0,
    MFACoveragePercent DECIMAL(6,2) NOT NULL DEFAULT 0,
    PrivilegedUsers INT NOT NULL DEFAULT 0,
    AdminsWithoutMFA INT NOT NULL DEFAULT 0,
    HighRiskUsers INT NOT NULL DEFAULT 0,
    SignInIssues INT NOT NULL DEFAULT 0,
    ExternalUsers INT NOT NULL DEFAULT 0,
    UnknownDevices INT NOT NULL DEFAULT 0,
    MultiplePrivilegedRoles INT NOT NULL DEFAULT 0,
    RiskDistributionJson JSON NOT NULL,
    AccessLevelCountsJson JSON NOT NULL,
    IdentityHealthScoresJson JSON NOT NULL,
    StackCTRLRiskScore DECIMAL(6,2) NULL,
    StackCTRLHealthScore DECIMAL(6,2) NULL,
    DashboardMetricsJson JSON NOT NULL,
    SourceAuditJson JSON NULL,
    EvidenceSha256 CHAR(64) NULL,
    IncompleteReason TEXT NULL,
    ErrorMessage TEXT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    KEY ix_identity_evidence_latest (CompanyID, IsComplete, CollectedAt, ID),
    KEY ix_identity_evidence_status (CollectionStatus, CollectedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLIdentityUserEvidence (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    SnapshotID BIGINT UNSIGNED NOT NULL,
    CompanyID BIGINT NOT NULL,
    TenantKey VARCHAR(100) NOT NULL,
    UserSourceID VARCHAR(255) NULL,
    Name VARCHAR(500) NOT NULL,
    Email VARCHAR(500) NULL,
    JobTitle VARCHAR(500) NULL,
    RolesText TEXT NULL,
    RolesJson JSON NOT NULL,
    UserType VARCHAR(50) NOT NULL,
    MFAEnabled TINYINT(1) NOT NULL DEFAULT 0,
    AuthMethodCount INT NOT NULL DEFAULT 0,
    RiskLevel VARCHAR(50) NOT NULL,
    AccountStatus VARCHAR(50) NOT NULL,
    LastSignInAt DATETIME NULL,
    DaysSinceLastSignIn INT NULL,
    SignInStatus VARCHAR(100) NULL,
    Location VARCHAR(500) NULL,
    Device VARCHAR(500) NULL,
    Phone VARCHAR(255) NULL,
    ProcessedEvidenceJson JSON NOT NULL,
    CollectedAt DATETIME(3) NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_identity_user_snapshot_source (SnapshotID, UserSourceID),
    KEY ix_identity_user_evidence_snapshot (SnapshotID, ID),
    KEY ix_identity_user_evidence_company_email (CompanyID, Email),
    CONSTRAINT fk_identity_user_evidence_snapshot
        FOREIGN KEY (SnapshotID) REFERENCES StackCTRLIdentityEvidenceSnapshots(ID)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLEnterpriseReportRuns (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    PeriodType VARCHAR(30) NOT NULL,
    PeriodStart DATE NOT NULL,
    PeriodEnd DATE NOT NULL,
    Status VARCHAR(80) NOT NULL DEFAULT 'queued',
    Mode VARCHAR(100) NOT NULL,
    DeduplicationKey VARCHAR(255) NULL,
    StartedAt DATETIME NULL,
    CompletedAt DATETIME NULL,
    TotalInputTokens BIGINT NOT NULL DEFAULT 0,
    TotalOutputTokens BIGINT NOT NULL DEFAULT 0,
    TotalTokens BIGINT NOT NULL DEFAULT 0,
    TotalRequestBytes BIGINT NOT NULL DEFAULT 0,
    TotalResponseBytes BIGINT NOT NULL DEFAULT 0,
    RetryCount INT NOT NULL DEFAULT 0,
    ErrorMessage TEXT NULL,
    ProgressJson JSON NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_enterprise_run_dedupe (DeduplicationKey),
    KEY ix_enterprise_run_company (CompanyID, ID),
    KEY ix_enterprise_run_status (Status, StartedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLTenantDomainIntelligence (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    RunID BIGINT UNSIGNED NOT NULL,
    DomainKey VARCHAR(100) NOT NULL,
    DomainName VARCHAR(180) NOT NULL,
    PeriodType VARCHAR(30) NOT NULL,
    PeriodStart DATE NOT NULL,
    PeriodEnd DATE NOT NULL,
    HealthScore DECIMAL(8,2) NULL,
    RiskScore DECIMAL(8,2) NULL,
    RiskLevel VARCHAR(50) NULL,
    InputSizeBytes BIGINT NOT NULL DEFAULT 0,
    ResponseSizeBytes BIGINT NOT NULL DEFAULT 0,
    InputTokens BIGINT NOT NULL DEFAULT 0,
    OutputTokens BIGINT NOT NULL DEFAULT 0,
    TotalTokens BIGINT NOT NULL DEFAULT 0,
    RetryCount INT NOT NULL DEFAULT 0,
    Status VARCHAR(80) NOT NULL,
    AnalysisJson JSON NULL,
    DomainExecutiveSummary TEXT NULL,
    TechnicalSummary TEXT NULL,
    BusinessImpact TEXT NULL,
    CurrentPosture TEXT NULL,
    EvidenceSummary TEXT NULL,
    ScoreJustification TEXT NULL,
    ControlAssessment JSON NULL,
    FindingsJson JSON NULL,
    RisksJson JSON NULL,
    RecommendationsJson JSON NULL,
    TrendAnalysisJson JSON NULL,
    YesterdayVsTodayJson JSON NULL,
    MissingDataWarningsJson JSON NULL,
    AssumptionsJson JSON NULL,
    ConfidenceScore DECIMAL(8,4) NULL,
    ErrorMessage TEXT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_domain_intelligence_run (RunID, DomainKey),
    KEY ix_domain_intelligence_company (CompanyID, RunID, DomainKey),
    KEY ix_domain_intelligence_status (Status, CreatedAt),
    KEY ix_domain_intelligence_latest_lookup (CompanyID, DomainKey, Status, ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS StackCTRLTenantDomainIntelligenceBatches (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    RunID BIGINT UNSIGNED NOT NULL,
    DomainKey VARCHAR(100) NOT NULL,
    DomainName VARCHAR(180) NOT NULL,
    BatchNumber INT NOT NULL,
    BatchCount INT NOT NULL,
    Status VARCHAR(80) NOT NULL,
    StackCTRLDataCount INT NOT NULL DEFAULT 0,
    BatchItemCount INT NOT NULL DEFAULT 0,
    SentToAzureCount INT NOT NULL DEFAULT 0,
    RemainingAfterBatch INT NOT NULL DEFAULT 0,
    OmittedFromThisBatch INT NOT NULL DEFAULT 0,
    InputSizeBytes BIGINT NOT NULL DEFAULT 0,
    ResponseSizeBytes BIGINT NOT NULL DEFAULT 0,
    InputTokens BIGINT NOT NULL DEFAULT 0,
    OutputTokens BIGINT NOT NULL DEFAULT 0,
    TotalTokens BIGINT NOT NULL DEFAULT 0,
    RetryCount INT NOT NULL DEFAULT 0,
    BatchSummaryJson JSON NULL,
    FindingsJson JSON NULL,
    RisksJson JSON NULL,
    RecommendationsJson JSON NULL,
    TrendsJson JSON NULL,
    MissingDataWarningsJson JSON NULL,
    StartedAt DATETIME NULL,
    CompletedAt DATETIME NULL,
    ErrorMessage TEXT NULL,
    FailureReason TEXT NULL,
    RawResponsePreview LONGTEXT NULL,
    AzureFinishReason VARCHAR(100) NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_domain_batch (RunID, DomainKey, BatchNumber),
    KEY ix_domain_batch_company (CompanyID, RunID, DomainKey),
    KEY ix_domain_batch_status (Status, CreatedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLEnterpriseSynthesis (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    RunID BIGINT UNSIGNED NOT NULL,
    PeriodType VARCHAR(30) NOT NULL,
    PeriodStart DATE NOT NULL,
    PeriodEnd DATE NOT NULL,
    Status VARCHAR(80) NOT NULL,
    ExecutiveSummaryJson JSON NULL,
    BoardReportJson JSON NULL,
    ManagementReportJson JSON NULL,
    RiskRegisterJson JSON NULL,
    RecommendationsJson JSON NULL,
    TrendAnalysisJson JSON NULL,
    ComplianceReviewJson JSON NULL,
    GovernanceReviewJson JSON NULL,
    DomainScorecardJson JSON NULL,
    MaturityAssessmentJson JSON NULL,
    BusinessImpactSummary TEXT NULL,
    TopDecisionsRequiredJson JSON NULL,
    Next30DaysPlanJson JSON NULL,
    Next90DaysPlanJson JSON NULL,
    EvidenceJustificationJson JSON NULL,
    LimitationsJson JSON NULL,
    PowerBISummaryJson JSON NULL,
    InputSizeBytes BIGINT NOT NULL DEFAULT 0,
    ResponseSizeBytes BIGINT NOT NULL DEFAULT 0,
    InputTokens BIGINT NOT NULL DEFAULT 0,
    OutputTokens BIGINT NOT NULL DEFAULT 0,
    TotalTokens BIGINT NOT NULL DEFAULT 0,
    RetryCount INT NOT NULL DEFAULT 0,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_enterprise_synthesis_run (RunID),
    KEY ix_enterprise_synthesis_company (CompanyID, RunID),
    KEY ix_enterprise_synthesis_latest_lookup (CompanyID, Status, ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS StackCTRLIntelligenceEvidenceAudit (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    RunID BIGINT UNSIGNED NOT NULL,
    DomainKey VARCHAR(100) NOT NULL,
    StackCTRLDataCount INT NOT NULL DEFAULT 0,
    SentToAzureCount INT NOT NULL DEFAULT 0,
    OmittedCount INT NOT NULL DEFAULT 0,
    MetricsIncludedCount INT NOT NULL DEFAULT 0,
    EvidenceIncludedCount INT NOT NULL DEFAULT 0,
    EvidenceOmittedCount INT NOT NULL DEFAULT 0,
    HistoricalComparisonsIncluded INT NOT NULL DEFAULT 0,
    AzureMentionedDomain TINYINT(1) NOT NULL DEFAULT 0,
    RisksReturnedCount INT NOT NULL DEFAULT 0,
    RecommendationsReturnedCount INT NOT NULL DEFAULT 0,
    TrendsReturnedCount INT NOT NULL DEFAULT 0,
    InputSizeBytes BIGINT NOT NULL DEFAULT 0,
    OutputSizeBytes BIGINT NOT NULL DEFAULT 0,
    InputTokens BIGINT NOT NULL DEFAULT 0,
    OutputTokens BIGINT NOT NULL DEFAULT 0,
    RetryCount INT NOT NULL DEFAULT 0,
    Status VARCHAR(80) NOT NULL,
    AzureInputSummaryJson JSON NULL,
    OmittedSummaryJson JSON NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    UNIQUE KEY uq_evidence_audit_run_domain (RunID, DomainKey),
    KEY ix_evidence_audit_company (CompanyID, RunID, DomainKey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLEnterpriseIntelligenceItems (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    CompanyID BIGINT NOT NULL,
    SnapshotID BIGINT UNSIGNED NULL,
    RunID BIGINT UNSIGNED NOT NULL,
    DomainKey VARCHAR(100) NOT NULL,
    DomainName VARCHAR(180) NOT NULL,
    PeriodType VARCHAR(30) NOT NULL,
    PeriodStart DATE NOT NULL,
    PeriodEnd DATE NOT NULL,
    ItemType VARCHAR(50) NOT NULL,
    Title VARCHAR(255) NOT NULL,
    Description TEXT NULL,
    Severity VARCHAR(50) NULL,
    Priority VARCHAR(50) NULL,
    Status VARCHAR(50) NULL,
    Likelihood VARCHAR(80) NULL,
    Impact VARCHAR(120) NULL,
    BusinessImpact TEXT NULL,
    EvidenceSummary TEXT NULL,
    Recommendation TEXT NULL,
    SuggestedOwner VARCHAR(180) NULL,
    SuggestedDueDate DATE NULL,
    Direction VARCHAR(50) NULL,
    CurrentValue DECIMAL(20,4) NULL,
    PreviousValue DECIMAL(20,4) NULL,
    ChangePercent DECIMAL(20,4) NULL,
    ComparisonPeriod VARCHAR(50) NULL,
    SourceStage VARCHAR(50) NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    KEY ix_enterprise_item_run (RunID, DomainKey, ItemType),
    KEY ix_enterprise_item_company (CompanyID, CreatedAt),
    KEY ix_enterprise_item_due (SuggestedDueDate, Status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS StackCTRLKnowledgeBase (
    ID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    DomainKey VARCHAR(100) NOT NULL,
    Title VARCHAR(255) NOT NULL,
    SourceType VARCHAR(100) NULL,
    SourceUrl VARCHAR(1000) NULL,
    ContentSummary TEXT NULL,
    BestPracticeJson JSON NULL,
    IsActive TINYINT(1) NOT NULL DEFAULT 1,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ID),
    KEY ix_knowledge_domain_active (DomainKey, IsActive, UpdatedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_EnterpriseRuns AS
SELECT r.ID AS RunID, r.CompanyID, c.CompanyName, r.SnapshotID, r.PeriodType,
       r.PeriodStart AS ReportDate, r.PeriodEnd, r.Status, r.Mode,
       r.TotalInputTokens, r.TotalOutputTokens, r.TotalTokens, r.RetryCount,
       r.StartedAt, r.CompletedAt, r.ErrorMessage
FROM StackCTRLEnterpriseReportRuns r
LEFT JOIN Companies c ON c.ID = r.CompanyID;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainIntelligence AS
SELECT d.ID AS DomainIntelligenceID, d.RunID, d.CompanyID, d.SnapshotID,
       d.DomainKey, d.DomainName, d.PeriodType, d.PeriodStart AS ReportDate, d.PeriodEnd,
       d.HealthScore, d.RiskScore, d.RiskLevel, d.Status AS OutputStatus,
       d.DomainExecutiveSummary, d.TechnicalSummary, d.BusinessImpact,
       d.CurrentPosture, d.EvidenceSummary, d.ScoreJustification,
       d.ConfidenceScore, d.InputTokens, d.OutputTokens, d.TotalTokens,
       d.RetryCount, d.CreatedAt
FROM StackCTRLTenantDomainIntelligence d;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainFindings AS
SELECT item.ID AS FindingID, item.RunID, item.CompanyID, item.SnapshotID,
       item.DomainKey, item.DomainName, item.PeriodType, item.PeriodStart AS ReportDate,
       item.Title, item.Description, item.Severity, item.Status,
       item.BusinessImpact, item.EvidenceSummary, item.Recommendation,
       item.SuggestedOwner, item.SuggestedDueDate, item.CreatedAt
FROM StackCTRLEnterpriseIntelligenceItems item
WHERE item.ItemType = 'finding';

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainRisks AS
SELECT item.ID AS RiskID, item.RunID, item.CompanyID, item.SnapshotID,
       item.DomainKey, item.DomainName, item.PeriodType, item.PeriodStart AS ReportDate,
       item.Title, item.Description, item.Severity, item.Likelihood, item.Impact,
       item.BusinessImpact, item.EvidenceSummary, item.Recommendation,
       item.SuggestedOwner, item.SuggestedDueDate, item.CreatedAt
FROM StackCTRLEnterpriseIntelligenceItems item
WHERE item.ItemType = 'risk';

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainRecommendations AS
SELECT item.ID AS RecommendationID, item.RunID, item.CompanyID, item.SnapshotID,
       item.DomainKey, item.DomainName, item.PeriodType, item.PeriodStart AS ReportDate,
       item.Title, item.Description, item.Priority, item.Status,
       item.BusinessImpact, item.EvidenceSummary, item.Recommendation,
       item.SuggestedOwner, item.SuggestedDueDate, item.CreatedAt
FROM StackCTRLEnterpriseIntelligenceItems item
WHERE item.ItemType = 'recommendation';

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainTrends AS
SELECT item.ID AS TrendID, item.RunID, item.CompanyID, item.SnapshotID,
       item.DomainKey, item.DomainName, item.PeriodType, item.PeriodStart AS ReportDate,
       item.Title, item.Description, item.Direction, item.CurrentValue,
       item.PreviousValue, item.ChangePercent, item.ComparisonPeriod,
       item.EvidenceSummary, item.CreatedAt
FROM StackCTRLEnterpriseIntelligenceItems item
WHERE item.ItemType = 'trend';

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_DomainEvidenceAudit AS
SELECT audit.ID AS EvidenceAuditID, audit.RunID, audit.CompanyID, audit.SnapshotID,
       audit.DomainKey, audit.StackCTRLDataCount, audit.SentToAzureCount,
       audit.OmittedCount, audit.MetricsIncludedCount, audit.EvidenceIncludedCount,
       audit.EvidenceOmittedCount, audit.HistoricalComparisonsIncluded,
       audit.AzureMentionedDomain, audit.RisksReturnedCount,
       audit.RecommendationsReturnedCount, audit.TrendsReturnedCount,
       audit.InputSizeBytes, audit.OutputSizeBytes, audit.InputTokens,
       audit.OutputTokens, audit.RetryCount, audit.Status, audit.CreatedAt
FROM StackCTRLIntelligenceEvidenceAudit audit;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_EnterpriseSynthesis AS
SELECT synthesis.ID AS SynthesisID, synthesis.RunID, synthesis.CompanyID,
       synthesis.SnapshotID, synthesis.PeriodType, synthesis.PeriodStart AS ReportDate,
       synthesis.PeriodEnd, synthesis.Status AS OutputStatus,
       JSON_UNQUOTE(JSON_EXTRACT(synthesis.ExecutiveSummaryJson, '$.summary')) AS EnterpriseExecutiveSummary,
       synthesis.BusinessImpactSummary, synthesis.InputTokens, synthesis.OutputTokens,
       synthesis.TotalTokens, synthesis.RetryCount, synthesis.CreatedAt
FROM StackCTRLEnterpriseSynthesis synthesis;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_EnterpriseBoardReport AS
SELECT synthesis.ID AS BoardReportID, synthesis.RunID, synthesis.CompanyID,
       synthesis.SnapshotID, synthesis.PeriodType, synthesis.PeriodStart AS ReportDate,
       synthesis.Status AS OutputStatus,
       JSON_UNQUOTE(JSON_EXTRACT(synthesis.BoardReportJson, '$.summary')) AS BoardSummary,
       synthesis.BusinessImpactSummary, synthesis.CreatedAt
FROM StackCTRLEnterpriseSynthesis synthesis;

CREATE OR REPLACE SQL SECURITY INVOKER VIEW vw_PowerBI_EnterpriseManagementActions AS
SELECT item.ID AS ActionID, item.RunID, item.CompanyID, item.SnapshotID,
       item.DomainKey, item.DomainName, item.PeriodType, item.PeriodStart AS ReportDate,
       item.Title, item.Description, item.Priority, item.Status,
       item.BusinessImpact, item.EvidenceSummary, item.Recommendation,
       item.SuggestedOwner, item.SuggestedDueDate, item.SourceStage, item.CreatedAt
FROM StackCTRLEnterpriseIntelligenceItems item
WHERE item.ItemType = 'management_action';
