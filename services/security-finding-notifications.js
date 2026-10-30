const { normalizeSeverity } = require('./whatsapp');

const AUTO_NOTIFY_SEVERITIES = new Set(['critical', 'high']);
const HIGH_CONFIDENCE = 'high';

function text(value) {
    return value === null || value === undefined ? '' : String(value).replace(/\s+/g, ' ').trim();
}

function scenarioCoverageForFinding(finding = {}, scenarioCoverage = {}) {
    if (finding.detectionId === 'anonymous_ip_authentication') return scenarioCoverage.anonymousIpAuthentication;
    if (['risky_user_successful_sign_in', 'identity_risk_detection_successful_sign_in'].includes(finding.detectionId)) {
        return scenarioCoverage.riskyUserSuccessfulSignIn;
    }
    if (finding.detectionId === 'cloudflare_access_identity_correlation') return scenarioCoverage.cloudflareAccessMicrosoftCorrelation;
    if (String(finding.source || '').toLowerCase() === 'cloudflare') return scenarioCoverage.cloudflareCurrentApi;
    return null;
}

function latestEvidenceTime(finding = {}) {
    const times = (Array.isArray(finding.evidence) ? finding.evidence : [])
        .map(item => Date.parse(item?.eventTime))
        .filter(Number.isFinite);
    return times.length ? new Date(Math.max(...times)).toISOString() : null;
}

/**
 * Selects only findings whose Stack CTRL assessment is strong enough for an
 * automated notification. Microsoft source severity never upgrades a finding.
 */
function selectSecurityFindingNotifications(payload = {}) {
    const findings = Array.isArray(payload.findings) ? payload.findings : [];
    const scenarioCoverage = payload.scenarioCoverage || {};
    const eligible = [];
    const ineligible = [];

    findings.forEach(finding => {
        const reasons = [];
        const severity = normalizeSeverity(finding.severity);
        const confidence = text(finding.confidence).toLowerCase();
        const coverage = scenarioCoverageForFinding(finding, scenarioCoverage);
        const evidenceCount = Array.isArray(finding.evidence) ? finding.evidence.length : 0;

        if (finding.status !== 'correlated') reasons.push('finding is not a validated correlation');
        if (!AUTO_NOTIFY_SEVERITIES.has(severity)) reasons.push('Stack CTRL severity is not high or critical');
        if (confidence !== HIGH_CONFIDENCE) reasons.push('confidence is not high');
        if (coverage?.status && coverage.status !== 'evaluated') reasons.push(`scenario coverage is ${coverage.status}`);
        if (evidenceCount < 2) reasons.push('fewer than two cited evidence records');
        if (!text(finding.impact)) reasons.push('impact is missing');
        if (!text(finding.recommendedAction)) reasons.push('recommended action is missing');
        if (/legacy .*compatibility|excluded from correlation and notification/i.test(text(finding.assessmentBasis))) {
            reasons.push('legacy compatibility evidence is not notification eligible');
        }

        if (reasons.length) {
            ineligible.push({
                findingId: finding.id || null,
                title: text(finding.title) || 'Security finding',
                reasons
            });
            return;
        }

        const user = Array.isArray(finding.affectedEntities?.users) ? finding.affectedEntities.users[0] : null;
        const ipAddress = Array.isArray(finding.affectedEntities?.ipAddresses) ? finding.affectedEntities.ipAddresses[0] : null;
        eligible.push({
            id: finding.id,
            findingId: finding.id,
            recordType: 'finding',
            type: 'finding',
            issue: [text(finding.title), text(finding.impact)].filter(Boolean).join(' — '),
            severity,
            confidence,
            source: 'Stack CTRL evidence-backed finding',
            category: finding.detectionId || 'security_finding',
            eventTime: latestEvidenceTime(finding),
            timestamp: latestEvidenceTime(finding),
            status: finding.status,
            user,
            userPrincipalName: user,
            ipAddress,
            action: text(finding.recommendedAction),
            findingEvidenceCount: evidenceCount
        });
    });

    return { eligible, ineligible };
}

module.exports = {
    selectSecurityFindingNotifications
};
