const crypto = require('crypto');

const ANONYMOUS_IP_PATTERN = /\b(?:anonymous\s+(?:ip|proxy)|tor|anonymi[sz]er)\b/i;

function text(value) {
    return value === null || value === undefined ? '' : String(value).trim();
}

function normalizeIdentity(value) {
    return text(value).toLowerCase();
}

function getUserKeys(record = {}, includeRecordId = false) {
    return new Set([
        record.userId,
        includeRecordId ? record.id : null,
        record.userPrincipalName,
        record.user,
        record.userEmail
    ].map(normalizeIdentity).filter(Boolean));
}

function getIp(record = {}) {
    const value = normalizeIdentity(record.ipAddress || record.clientIpAddress || record.sourceIpAddress || record.ip);
    return ['unknown', 'n/a', 'none', ''].includes(value) ? '' : value;
}

function getIps(record = {}) {
    const supplied = Array.isArray(record.ipAddresses) ? record.ipAddresses : [];
    return [...new Set([
        ...supplied.map(value => normalizeIdentity(value)),
        getIp(record)
    ].filter(value => value && !['unknown', 'n/a', 'none'].includes(value)))];
}

function getSignInOutcome(signIn = {}) {
    const outcome = normalizeIdentity(signIn.outcome || signIn.status);
    if (outcome === 'success' || outcome === 'succeeded') return 'success';
    if (outcome === 'failed' || outcome === 'failure') return 'failed';
    const errorCode = signIn.status?.errorCode;
    if (errorCode !== null && errorCode !== undefined && errorCode !== '') {
        const numericErrorCode = Number(errorCode);
        if (Number.isFinite(numericErrorCode)) return numericErrorCode === 0 ? 'success' : 'failed';
    }
    return 'unknown';
}

const IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM = 500;
const IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH = 1000;

function numericCoordinate(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
}

function signInCoordinates(signIn = {}) {
    const latitude = numericCoordinate(signIn.locationCoordinates?.latitude);
    const longitude = numericCoordinate(signIn.locationCoordinates?.longitude);
    return latitude !== null && longitude !== null && latitude >= -90 && latitude <= 90 && longitude >= -180 && longitude <= 180
        ? { latitude, longitude }
        : null;
}

function distanceKm(left, right) {
    const radians = degrees => degrees * (Math.PI / 180);
    const earthRadiusKm = 6371;
    const latitudeDelta = radians(right.latitude - left.latitude);
    const longitudeDelta = radians(right.longitude - left.longitude);
    const value = Math.sin(latitudeDelta / 2) ** 2 +
        Math.cos(radians(left.latitude)) * Math.cos(radians(right.latitude)) * Math.sin(longitudeDelta / 2) ** 2;
    return earthRadiusKm * (2 * Math.atan2(Math.sqrt(value), Math.sqrt(1 - value)));
}

function travelUserKey(signIn = {}) {
    return normalizeIdentity(signIn.userId || signIn.userPrincipalName || signIn.user);
}

function analyseImpossibleTravel(signIns = []) {
    const usable = signIns.filter(signIn =>
        getSignInOutcome(signIn) === 'success' &&
        travelUserKey(signIn) &&
        signInCoordinates(signIn) &&
        recordTime(signIn) !== null &&
        text(signIn.country).toLowerCase() !== 'unknown'
    );
    const byUser = new Map();
    usable.forEach(signIn => {
        const key = travelUserKey(signIn);
        const rows = byUser.get(key) || [];
        rows.push(signIn);
        byUser.set(key, rows);
    });
    const candidates = [];
    let comparablePairCount = 0;
    byUser.forEach(rows => {
        const ordered = [...rows].sort((left, right) => recordTime(left) - recordTime(right));
        let strongest = null;
        for (let index = 1; index < ordered.length; index += 1) {
            const earlier = ordered[index - 1];
            const later = ordered[index];
            if (normalizeIdentity(earlier.country) === normalizeIdentity(later.country)) continue;
            const elapsedHours = (recordTime(later) - recordTime(earlier)) / (60 * 60 * 1000);
            if (elapsedHours <= 0) continue;
            comparablePairCount += 1;
            const distance = distanceKm(signInCoordinates(earlier), signInCoordinates(later));
            const speed = distance / elapsedHours;
            if (distance < IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM || speed < IMPOSSIBLE_TRAVEL_MIN_SPEED_KMH) continue;
            if (!strongest || speed > strongest.speedKmh) {
                strongest = { userKey: travelUserKey(later), earlier, later, distanceKm: distance, elapsedHours, speedKmh: speed };
            }
        }
        if (strongest) candidates.push(strongest);
    });
    return {
        coordinateSignInCount: usable.length,
        identitiesWithCoordinates: [...byUser.values()].filter(rows => rows.length >= 2).length,
        comparablePairCount,
        candidates
    };
}

function evidenceReference(sourceType, record, summary) {
    const details = sourceType === 'sign_in'
        ? {
            userId: record.userId || null,
            userPrincipalName: record.userPrincipalName || record.user || null,
            outcome: getSignInOutcome(record),
            ipAddress: record.ipAddress || null,
            location: record.location || null,
            locationCoordinates: record.locationCoordinates || null,
            deviceName: record.deviceName || null,
            application: record.appDisplayName || null,
            riskLevel: record.riskLevel || null,
            conditionalAccessStatus: record.conditionalAccessStatus || null
        }
        : sourceType === 'risky_user'
            ? {
                userId: record.id || record.userId || null,
                userPrincipalName: record.userPrincipalName || null,
                displayName: record.userDisplayName || null,
                riskLevel: record.riskLevel || null,
                riskState: record.riskState || null,
                riskDetail: record.riskDetail || null
            }
            : sourceType === 'risk_detection'
                ? {
                    userId: record.userId || null,
                    userPrincipalName: record.userPrincipalName || null,
                    eventType: record.riskEventType || null,
                    riskLevel: record.riskLevel || null,
                    riskState: record.riskState || null,
                    riskDetail: record.riskDetail || null,
                    ipAddress: record.ipAddress || null
                }
                : {
                    sourceSystem: record.reportingSecuritySystem || record.source || record.vendor || null,
                    title: record.title || null,
                    description: record.description || null,
                    severity: record.severity || null,
                    user: record.user || record.userPrincipalName || null,
                    ipAddress: record.ipAddress || null
                };

    return {
        sourceType,
        sourceId: text(record.id || record.requestId) || null,
        eventTime: record.eventTime || record.timestamp || record.createdDateTime || record.activityDateTime || null,
        summary,
        details
    };
}

function createFindingId(detectionKey, anchor) {
    const key = `${detectionKey}|${text(anchor).toLowerCase()}`;
    return crypto.createHash('sha256').update(key).digest('hex').slice(0, 32);
}

function buildAnonymousIpFindings(alerts, signIns) {
    return alerts.filter(alert => {
        const description = [alert.title, alert.description, alert.category, alert.apiCategory].map(text).join(' ');
        return ANONYMOUS_IP_PATTERN.test(description);
    }).map(alert => {
        const ipAddresses = getIps(alert);
        const ipAddress = ipAddresses[0] || '';
        const sourceSystem = text(alert.reportingSecuritySystem || alert.source || alert.vendor) || 'Security provider';
        const compatibilityOnly = ['legacy_alerts', 'legacy_alerts_compatibility'].includes(alert.sourceSchema);
        const relatedSignIns = !compatibilityOnly && ipAddresses.length
            ? signIns.filter(signIn => ipAddresses.includes(getIp(signIn)))
            : [];
        const alertSummary = [
            text(alert.title) || `${sourceSystem} reported an anonymous-IP indicator`,
            ipAddresses.length ? `IP ${ipAddresses.join(', ')}` : ''
        ].filter(Boolean).join(' — ');
        const evidence = [
            evidenceReference('security_alert', alert, alertSummary),
            ...relatedSignIns.map(signIn => evidenceReference(
                'sign_in',
                signIn,
                [
                    text(signIn.outcome || signIn.status).toLowerCase() === 'unknown' ? 'Authentication outcome unknown' : `${signIn.outcome || signIn.status} sign-in`,
                    text(signIn.userPrincipalName || signIn.user) || 'Unknown user',
                    ipAddress ? `IP ${ipAddress}` : '',
                    signIn.eventTime || signIn.timestamp || ''
                ].filter(Boolean).join(' — ')
            ))
        ];
        const successfulSignIns = relatedSignIns.filter(signIn => getSignInOutcome(signIn) === 'success');
        const candidateUsers = [...new Set(relatedSignIns.map(signIn =>
            text(signIn.userPrincipalName || signIn.user).toLowerCase()
        ).filter(user => user && user !== 'unknown' && user !== 'unknown user'))];
        const title = ipAddress
            ? `Anonymous-IP activity observed from ${ipAddress}`
            : `Anonymous-IP indicator reported by ${sourceSystem}`;
        const userSummary = candidateUsers.length
            ? ` Candidate account(s) seen on this IP: ${candidateUsers.join(', ')}.`
            : '';

        return {
            id: createFindingId(
                'anonymous_ip_authentication',
                alert.id || `${ipAddress}|${alert.eventTime || alert.timestamp || alert.created || alert.title || 'anonymous-ip'}`
            ),
            detectionId: 'anonymous_ip_authentication',
            title,
            description: compatibilityOnly
                ? `${sourceSystem} reported an anonymous-IP indicator through the legacy Graph alerts compatibility source. It remains visible for investigation, but is not used for Stack CTRL correlation or notification because typed alert evidence is unavailable.`
                : relatedSignIns.length
                ? `${sourceSystem} reported an anonymous-IP indicator. ${relatedSignIns.length} possible sign-in record(s) from the same IP were found in the collected period, including ${successfulSignIns.length} successful authentication(s).${userSummary} IP equality alone does not prove the records are the same activity or establish account compromise.`
                : `${sourceSystem} reported an anonymous-IP indicator, but no matching sign-in record was available in the collected evidence. This indicator alone does not establish account compromise.`,
            impact: compatibilityOnly
                ? 'The provider observation remains available for analyst review, but its legacy data shape cannot establish the affected account or authentication activity.'
                : relatedSignIns.length
                ? `A sign-in was recorded from an IP ${sourceSystem} associated with anonymous infrastructure; review the account and authentication context.`
                : 'The IP indicator warrants review, but current evidence does not establish an authentication attempt or affected account.',
            severity: 'unassessed',
            sourceSeverity: text(alert.sourceSeverity || alert.severity) || null,
            confidence: relatedSignIns.length ? 'medium' : 'low',
            confidenceReason: compatibilityOnly
                ? 'The alert came from the temporary legacy compatibility source without typed evidence.'
                : relatedSignIns.length
                ? 'The evidence shares an exact IP address; time-window and account attribution are not established.'
                : 'Only the Microsoft-reported indicator is available; no matching sign-in was found.',
            status: relatedSignIns.length ? 'related_evidence' : 'needs_investigation',
            affectedEntities: {
                users: [],
                devices: [],
                ipAddresses
            },
            candidateUsers,
            evidence,
            recommendedAction: compatibilityOnly
                ? 'Review the provider alert in Microsoft Defender; do not notify from this legacy observation without independently corroborating evidence.'
                : relatedSignIns.length
                ? 'Review the matching sign-in outcomes, user, device and identity-risk state before deciding on containment.'
                : 'Check Microsoft sign-in and identity-risk records for this IP; do not treat the indicator alone as proof of compromise.',
            assessmentBasis: compatibilityOnly
                ? 'Legacy Graph alert retained temporarily as an observation only; it is excluded from correlation and notification.'
                : 'Stack CTRL links the security alert to collected sign-ins using an exact IP match. Severity remains unassessed pending validated impact criteria.'
        };
    });
}

function buildRiskyUserFindings(riskyUsers, riskDetections, signIns) {
    return riskyUsers.map(riskyUser => {
        const userKeys = getUserKeys(riskyUser, true);
        const relatedRiskDetections = riskDetections.filter(detection =>
            [...getUserKeys(detection)].some(key => userKeys.has(key))
        );
        const relatedSignIns = signIns.filter(signIn =>
            [...getUserKeys(signIn)].some(key => userKeys.has(key))
        );
        const successfulSignIns = relatedSignIns.filter(signIn => getSignInOutcome(signIn) === 'success');
        const userLabel = text(riskyUser.userPrincipalName || riskyUser.userDisplayName) || 'Risky user';
        const evidence = [
            evidenceReference(
                'risky_user',
                riskyUser,
                `${userLabel} — risk ${text(riskyUser.riskLevel) || 'unspecified'}, state ${text(riskyUser.riskState) || 'unspecified'}`
            ),
            ...relatedRiskDetections.map(detection => evidenceReference(
                'risk_detection',
                detection,
                [
                    text(detection.riskEventType) || 'Identity risk detection',
                    text(detection.riskLevel) ? `risk ${text(detection.riskLevel)}` : '',
                    detection.activityDateTime || detection.detectedDateTime || ''
                ].filter(Boolean).join(' — ')
            )),
            ...relatedSignIns.map(signIn => evidenceReference(
                'sign_in',
                signIn,
                `${getSignInOutcome(signIn)} sign-in — ${text(signIn.ipAddress) || 'IP unavailable'} — ${signIn.eventTime || signIn.timestamp || ''}`
            ))
        ];
        const title = successfulSignIns.length
            ? `Successful sign-in observed for risky user ${userLabel}`
            : `Microsoft reports identity risk for ${userLabel}`;

        return {
            id: createFindingId('risky_user_successful_sign_in', riskyUser.id || userLabel),
            detectionId: 'risky_user_successful_sign_in',
            title,
            description: successfulSignIns.length
                ? `Microsoft lists this user as risky and ${successfulSignIns.length} successful sign-in record(s) matched by user ID or principal name in the collected period. This is an investigation lead, not proof that the account or session was compromised.`
                : `Microsoft lists this user as risky, but no matching successful sign-in was found in the collected records. ${relatedSignIns.length} additional matching record(s) did not have a successful outcome.`,
            impact: successfulSignIns.length
                ? 'A successful authentication was recorded for an identity Microsoft currently reports as risky.'
                : 'The identity-risk state is present; no matching successful sign-in was observed in the collected records.',
            severity: 'unassessed',
            sourceRiskLevel: text(riskyUser.riskLevel) || null,
            sourceRiskState: text(riskyUser.riskState) || null,
            confidence: successfulSignIns.length ? 'high' : 'low',
            confidenceReason: successfulSignIns.length
                ? 'User identity matched by Microsoft user ID or case-insensitive principal name; compromise is not established.'
                : 'The Microsoft risky-user record is present, but no matching successful sign-in was found.',
            status: successfulSignIns.length ? 'correlated' : 'needs_investigation',
            affectedEntities: { users: [userLabel], devices: [], ipAddresses: [] },
            evidence,
            recommendedAction: successfulSignIns.length
                ? 'Review sign-in context, device and session evidence, then check the Microsoft identity-risk remediation state.'
                : 'Review the user’s Microsoft identity-risk state and remediation status.',
            assessmentBasis: 'Microsoft identity-risk state and sign-in outcome are retained as separate evidence. Stack CTRL severity remains unassessed pending validated impact criteria.'
        };
    });
}

const RISK_DETECTION_SIGNIN_WINDOW_MS = 24 * 60 * 60 * 1000;

function recordTime(value) {
    const candidate = value?.activityDateTime || value?.detectedDateTime || value?.eventTime || value?.timestamp || value?.createdDateTime;
    const parsed = Date.parse(candidate);
    return Number.isFinite(parsed) ? parsed : null;
}

function buildRiskDetectionSignInFindings(riskDetections, signIns) {
    const byUser = new Map();
    riskDetections.forEach(riskDetection => {
        const keys = [...getUserKeys(riskDetection)];
        if (!keys.length) return;
        const groupKey = keys.sort()[0];
        const group = byUser.get(groupKey) || { keys: new Set(keys), detections: [] };
        keys.forEach(key => group.keys.add(key));
        group.detections.push(riskDetection);
        byUser.set(groupKey, group);
    });

    return [...byUser.values()].map(group => {
        const userKeys = group.keys;
        const userLabel = text(group.detections.find(item => item.userPrincipalName)?.userPrincipalName || group.detections[0]?.userId) || 'an identified user';
        const timedDetections = group.detections.filter(item => recordTime(item) !== null);
        const relatedSignIns = timedDetections.length
            ? signIns.filter(signIn => {
                const signInTime = recordTime(signIn);
                if (signInTime === null || ![...getUserKeys(signIn)].some(key => userKeys.has(key))) return false;
                return timedDetections.some(detection => Math.abs(signInTime - recordTime(detection)) <= RISK_DETECTION_SIGNIN_WINDOW_MS);
            })
            : [];
        const successfulSignIns = relatedSignIns.filter(signIn => getSignInOutcome(signIn) === 'success');
        const detectionLabels = [...new Set(group.detections.map(item => text(item.riskEventType) || 'identity-risk event'))];
        const sourceRiskLevels = [...new Set(group.detections.map(item => text(item.riskLevel)).filter(Boolean))];
        const evidence = [
            ...group.detections.map(detection => evidenceReference(
                'risk_detection',
                detection,
                `${text(detection.riskEventType) || 'Identity-risk event'} — risk ${text(detection.riskLevel) || 'unspecified'} — ${userLabel}`
            )),
            ...relatedSignIns.map(signIn => evidenceReference(
                'sign_in',
                signIn,
                `${getSignInOutcome(signIn)} sign-in within 24 hours — ${text(signIn.ipAddress) || 'IP unavailable'} — ${signIn.eventTime || signIn.timestamp || ''}`
            ))
        ];

        return {
            id: createFindingId('identity_risk_detection_successful_sign_in', userLabel),
            detectionId: 'identity_risk_detection_successful_sign_in',
            title: successfulSignIns.length
                ? 'Successful sign-in near Microsoft identity-risk detection'
                : 'Microsoft identity-risk detection requires sign-in review',
            description: successfulSignIns.length
                ? `Microsoft recorded ${detectionLabels.join(', ')} for ${userLabel}; ${successfulSignIns.length} successful sign-in record(s) matched the same user within a 24-hour correlation window. This is an investigation lead, not proof that the account or session was compromised.`
                : timedDetections.length
                    ? `Microsoft recorded ${detectionLabels.join(', ')} for ${userLabel}, but no matching successful sign-in was found within 24 hours of the detection in the collected records.`
                    : `Microsoft recorded identity-risk evidence for ${userLabel}, but the detection timestamp was unavailable so Stack CTRL did not correlate sign-ins.`,
            impact: successfulSignIns.length
                ? 'A successful authentication was recorded near a Microsoft identity-risk detection for the same user.'
                : 'Identity-risk evidence was returned, but current evidence does not establish a time-bounded successful sign-in correlation.',
            severity: 'unassessed',
            sourceRiskLevel: sourceRiskLevels.join(', ') || null,
            confidence: successfulSignIns.length ? 'medium' : 'low',
            confidenceReason: successfulSignIns.length
                ? 'The identity-risk detection and sign-in matched by stable user identity within a 24-hour time window; compromise is not established.'
                : timedDetections.length
                    ? 'No successful sign-in matched the same user inside the 24-hour correlation window.'
                    : 'The returned identity-risk detection had no usable timestamp for time-bounded correlation.',
            status: successfulSignIns.length ? 'correlated' : 'needs_investigation',
            affectedEntities: { users: [userLabel], devices: [], ipAddresses: [] },
            candidateUsers: [userLabel],
            evidence,
            recommendedAction: successfulSignIns.length
                ? 'Review the time-bounded sign-in context, device and session evidence, then check Microsoft identity-risk remediation state.'
                : 'Review the identity-risk detection and its linked sign-in context; do not infer account compromise without corroborating evidence.',
            assessmentBasis: 'This finding groups Microsoft identity-risk detections by user and correlates only sign-ins for the same user within 24 hours. The risky-user feed is unavailable, and source values remain separate from Stack CTRL assessment.'
        };
    });
}

function buildImpossibleTravelFindings(signIns) {
    const analysis = analyseImpossibleTravel(signIns);
    return {
        ...analysis,
        findings: analysis.candidates.map(candidate => {
            const userLabel = text(candidate.later.userPrincipalName || candidate.later.user) || 'an identified user';
            const roundedDistance = Math.round(candidate.distanceKm);
            const roundedSpeed = Math.round(candidate.speedKmh);
            const roundedHours = Number(candidate.elapsedHours.toFixed(1));
            return {
                id: createFindingId('impossible_travel_candidate', `${candidate.userKey}|${candidate.earlier.id}|${candidate.later.id}`),
                detectionId: 'impossible_travel_candidate',
                title: 'Travel-velocity sign-in anomaly requires investigation',
                description: `Successful sign-ins for ${userLabel} were recorded from different countries ${roundedDistance} km apart, ${roundedHours} hour(s) apart, implying approximately ${roundedSpeed} km/h. This is a travel-velocity anomaly, not proof of impossible travel or account compromise.`,
                impact: 'A rapid location change can indicate proxy, VPN, token misuse, inaccurate location data, or legitimate travel; analyst context is required.',
                severity: 'unassessed',
                confidence: 'medium',
                confidenceReason: 'The same user has two successful sign-ins with valid coordinates and a calculated velocity above the conservative threshold. VPNs, proxies, mobile networks, and location accuracy can produce false positives.',
                status: 'needs_investigation',
                affectedEntities: {
                    users: [userLabel],
                    devices: [candidate.earlier.deviceName, candidate.later.deviceName].filter(Boolean),
                    ipAddresses: [candidate.earlier.ipAddress, candidate.later.ipAddress].filter(Boolean)
                },
                candidateUsers: [userLabel],
                evidence: [
                    evidenceReference('sign_in', candidate.earlier, `Earlier successful sign-in — ${candidate.earlier.location} — ${candidate.earlier.eventTime || candidate.earlier.timestamp}`),
                    evidenceReference('sign_in', candidate.later, `Later successful sign-in — ${candidate.later.location} — ${candidate.later.eventTime || candidate.later.timestamp}`)
                ],
                recommendedAction: 'Review both sign-ins, device/session context, known VPN or travel activity, and Microsoft identity-risk evidence before containment.',
                assessmentBasis: `Same-user successful sign-ins with valid coordinates crossed countries at an implied ${roundedSpeed} km/h. Stack CTRL does not label this impossible travel or compromise without human validation.`
            };
        })
    };
}

function buildSecurityFindings({
    alerts = [],
    signIns = [],
    riskyUsers = [],
    riskDetections = [],
    sourceStatuses = {}
} = {}) {
    const useRiskDetectionFallback = !riskyUsers.length && sourceStatuses.riskyUsers === 'unavailable';
    const impossibleTravel = buildImpossibleTravelFindings(signIns);
    const findings = [
        ...buildAnonymousIpFindings(alerts, signIns),
        ...buildRiskyUserFindings(riskyUsers, riskDetections, signIns),
        ...(useRiskDetectionFallback ? buildRiskDetectionSignInFindings(riskDetections, signIns) : []),
        ...impossibleTravel.findings
    ].sort((left, right) => left.title.localeCompare(right.title));
    const anonymousSources = [sourceStatuses.alerts, sourceStatuses.signIns].filter(Boolean);
    const identitySources = (useRiskDetectionFallback
        ? [sourceStatuses.riskDetections, sourceStatuses.signIns]
        : [sourceStatuses.riskyUsers, sourceStatuses.signIns]
    ).filter(Boolean);
    const coverageStatus = sources => {
        if (!sources.length) return 'not_assessed';
        if (sources.some(status => status === 'unavailable')) return 'unavailable';
        if (sources.some(status => status === 'partial')) return 'partial';
        return 'evaluated';
    };
    const anonymousStatus = coverageStatus(anonymousSources);
    const riskyUserStatus = coverageStatus(identitySources);

    return {
        findings,
        scenarioCoverage: {
            anonymousIpAuthentication: {
                status: anonymousStatus,
                findingCount: findings.filter(item => item.detectionId === 'anonymous_ip_authentication').length,
                reason: anonymousStatus === 'partial'
                    ? 'One or more source queries were incomplete; correlations use only the records returned.'
                    : anonymousStatus === 'unavailable'
                        ? 'Alerts or sign-in records were unavailable, so anonymous-IP correlation may be incomplete.'
                        : null
            },
            impossibleTravel: {
                status: !impossibleTravel.coordinateSignInCount
                    ? 'not_assessed'
                    : sourceStatuses.signIns === 'partial'
                        ? 'partial'
                        : 'evaluated',
                coordinateSignInCount: impossibleTravel.coordinateSignInCount,
                identitiesWithCoordinates: impossibleTravel.identitiesWithCoordinates,
                comparablePairCount: impossibleTravel.comparablePairCount,
                findingCount: impossibleTravel.findings.length,
                reason: !impossibleTravel.coordinateSignInCount
                    ? 'No successful sign-ins with both a stable user identity, valid location coordinates, timestamp, and country were returned.'
                    : 'Stack CTRL compares consecutive successful sign-ins for the same user across countries. A candidate requires valid coordinates, at least 500 km distance, and an implied speed of at least 1,000 km/h. VPNs, proxies, mobile networks, and location accuracy can produce false positives.'
            },
            riskyUserSuccessfulSignIn: {
                status: riskyUserStatus,
                reason: riskyUserStatus === 'unavailable'
                    ? 'Risky-user or sign-in records were unavailable, so this scenario could not be fully evaluated.'
                    : riskyUserStatus === 'partial'
                        ? useRiskDetectionFallback
                            ? 'Risky users are unavailable, so Stack CTRL used returned Microsoft identity-risk detections; one or more source queries were incomplete and correlations use only returned records.'
                            : 'One or more source queries were incomplete; correlations use only the records returned.'
                        : useRiskDetectionFallback
                            ? 'Risky users are unavailable, so Stack CTRL evaluated returned Microsoft identity-risk detections instead.'
                            : null
            }
        }
    };
}

module.exports = {
    buildSecurityFindings,
    getSignInOutcome
};
