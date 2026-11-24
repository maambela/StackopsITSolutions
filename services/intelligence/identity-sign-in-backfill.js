const DAY = 86400000;
const HOUR = 3600000;

function backfillPlan(saved, now) {
    const end = Math.floor(now / DAY) * DAY;
    const start = end - 30 * DAY;
    const ranges = saved?.ranges?.filter(range => range.start >= start && range.end <= end) || [];
    for (let day = start; day < end; day += DAY) {
        if (!ranges.some(range => range.start >= day && range.start < day + DAY)) {
            ranges.push({ start: day, end: day + DAY, status: 'pending' });
        }
    }
    return { retryAt: saved?.retryAt || 0, ranges: ranges.sort((a, b) => b.end - a.end),
        records: (saved?.records || []).filter(record => Date.parse(record.createdDateTime) >= now - 30 * DAY) };
}

function nextBackfillRange(state, now) {
    if (state.retryAt > now) return undefined;
    return state.ranges.find(range => range.status !== 'complete' && (range.retryAt || 0) <= now);
}

function finishBackfillRange(state, range, result, now) {
    const index = state.ranges.indexOf(range);
    const complete = result.ok && !result.hasMore && !result.warnings?.length;
    if (complete) {
        state.ranges[index] = { start: range.start, end: range.end, status: 'complete' };
    } else if (result.pageLimitReached && result.hasMore && result.ok && range.end - range.start > HOUR) {
        const middle = Math.floor((range.start + range.end) / 2);
        state.ranges.splice(index, 1, { start: middle, end: range.end, status: 'pending' },
            { start: range.start, end: middle, status: 'pending' });
    } else {
        const delay = result.pageLimitReached && result.ok ? HOUR : 120000;
        state.ranges[index] = { start: range.start, end: range.end, status: 'incomplete',
            retryAt: now + Math.max(delay, Number(result.retryAfterMs) || 0) };
        if (result.httpStatus === 429) state.retryAt = state.ranges[index].retryAt;
    }
    const latest = new Map();
    for (const record of [...state.records, ...(Array.isArray(result.value) ? result.value.filter(event => {
        const time = Date.parse(event.createdDateTime);
        return time >= range.start && time < range.end;
    }) : [])]) {
        const principal = record.userId ? 'id:' + String(record.userId).toLowerCase()
            : 'upn:' + String(record.userPrincipalName || '').trim().toLowerCase();
        if (principal === 'upn:') continue;
        const code = record.status?.errorCode;
        const key = principal + (code != null && String(code) !== '0' ? ':failure' : ':other');
        const old = latest.get(key);
        if (!old || Date.parse(record.createdDateTime) > Date.parse(old.createdDateTime)) latest.set(key, record);
    }
    state.records = [...latest.values()];
    return state;
}
async function withBackfillLock(pool, companyId, tenantId, task) {
    const { createHash } = require('node:crypto');
    const key = createHash('sha256').update(JSON.stringify(['identity-sign-ins', companyId, tenantId.toLowerCase()])).digest('hex');
    const connection = await pool.getConnection();
    let locked = false;
    let lockKnown = false;
    try {
        const [[row]] = await connection.query('SELECT GET_LOCK(?, 0) AS locked', [key]);
        lockKnown = true;
        locked = Number(row?.locked) === 1;
        if (locked) return await task(connection);
    } finally {
        try {
            if (!lockKnown) {
                connection.destroy();
            } else {
                if (locked) await connection.query('SELECT RELEASE_LOCK(?)', [key]);
                connection.release();
            }
        } catch (error) {
            connection.destroy();
            throw error;
        }
    }
}

function mergeBackfillUsers(users, saved, fetchedAt, current, now = Date.now()) {
    if (!saved) return users;
    const plan = backfillPlan(saved, now);
    const today = Math.floor(now / DAY) * DAY;
    const recentAt = Date.parse(fetchedAt || '');
    const complete = plan.ranges.every(range => range.status === 'complete') &&
        current?.windowDays === 1 && current.status === 'complete' && recentAt >= today &&
        recentAt - DAY <= today && now - recentAt <= 30 * 60000;
    const byId = new Map();
    const byUpn = new Map();
    for (const record of plan.records) {
        const map = record.userId ? byId : byUpn;
        const key = String(record.userId || record.userPrincipalName || '').trim().toLowerCase();
        const entries = map.get(key) || [];
        entries.push(record);
        map.set(key, entries);
    }
    const upnCounts = new Map();
    for (const user of users) {
        const upn = String(user.userPrincipalName || '').trim().toLowerCase();
        upnCounts.set(upn, (upnCounts.get(upn) || 0) + 1);
    }
    return users.map(user => {
        let { lastSignIn, failedSignIn } = user;
        const upn = String(user.userPrincipalName || '').trim().toLowerCase();
        const events = [...(byId.get(String(user.id || '').toLowerCase()) || []),
            ...(upn && upnCounts.get(upn) === 1 ? byUpn.get(upn) || [] : [])];
        for (const record of events) {
            const code = record.status?.errorCode;
            const event = { dateTime: record.createdDateTime, status: code == null ? 'Unknown' : String(code) === '0' ? 'Success' : 'Failed',
                observationStatus: 'observed', errorCode: code, failureReason: record.status?.failureReason,
                appDisplayName: record.appDisplayName, device: record.deviceDetail?.displayName,
                location: [record.location?.city, record.location?.countryOrRegion].filter(Boolean).join(', ') };
            const time = Date.parse(event.dateTime);
            if (time > (Date.parse(lastSignIn?.dateTime) || 0)) lastSignIn = event;
            if (event.status === 'Failed' && time > (Date.parse(failedSignIn?.dateTime) || 0)) failedSignIn = event;
        }
        return { ...user, lastSignIn, failedSignIn, historyComplete: complete, historyVerifiedAt: complete ? fetchedAt : null };
    });
}

module.exports = { backfillPlan, nextBackfillRange, finishBackfillRange, withBackfillLock, mergeBackfillUsers };
