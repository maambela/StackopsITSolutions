
const sunbirdSecurityTableState={search:'',severity:'all',status:'all',source:'all',sort:'newest'};
let model={rawRecords:[],allEvents:[],rawEvidence:{},warnings:[],retrieval:{sources:[]}};
function buildSunbirdSecurityModel(){return model} function normalizeSunbirdSecurityData(data){return data}
function escapeIdentityText(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function sunbirdSecurityDisplayText(value, fallback = 'Not recorded') {
    if (value === null || value === undefined || value === '') return fallback;
    if (typeof value === 'object') {
        const readable = value.displayName || value.userPrincipalName || value.name || value.title || value.summary || value.message || value.id;
        return readable ? String(readable) : fallback;
    }
    return String(value);
}

function sunbirdSecurityEscape(value, fallback = 'Not recorded') {
    return escapeIdentityText(sunbirdSecurityDisplayText(value, fallback));
}

function sunbirdSecurityStatusClass(value) {
    const normalized = String(value || '').toLowerCase();
    if (/completed?.*warning|warning.*completed?|partial|related_evidence/.test(normalized)) return 'partial';
    if (/unavailable|not_assessed|needs_investigation|warning|error/.test(normalized)) return 'attention';
    if (/correlated|evaluated|complete|active|open/.test(normalized)) return 'observed';
    return 'neutral';
}

function sunbirdSecurityStatusLabel(value, fallback = 'Not recorded') {
    const text = sunbirdSecurityDisplayText(value, fallback);
    return text.replace(/([a-z\d])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\b\w/g, character => character.toUpperCase());
}

function sunbirdSecurityFormatTime(value) {
    if (!value || typeof value !== 'string' || !/[T ]\d{2}:\d{2}/.test(value)) return 'Not provided';
    const time = new Date(value);
    if (Number.isNaN(time.getTime())) return 'Not provided';
    return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone: 'Africa/Johannesburg' }).format(time) + ' SAST';
}

function getSunbirdSecurityMitre(item = {}) {
    return { tactic: 'Provider supplied', technique: item.mitreTechniques?.length ? item.mitreTechniques.join(', ') : 'Not provided' };
}

function getSunbirdSecurityApiSource(event = {}) {
    if (event.apiSource) return event.apiSource;
    const providerFallback = getSunbirdSecurityReportingSystem(event);
    if (event.recordType === 'alert') return event.serviceSource || event.productName || event.vendorInformation?.provider || event.vendor || providerFallback;
    if (event.recordType === 'incident') return event.providerName || event.serviceSource || providerFallback;
    if (event.recordType === 'signin') return event.appDisplayName || event.resourceDisplayName || event.clientAppUsed || providerFallback;
    if (event.recordType === 'indicator') return event.targetProduct || providerFallback;
    return event.cloudflareApiSignal ? (event.source || 'Cloudflare') : providerFallback;
}

function getSunbirdSecurityReportingSystem(event = {}) {
    const sourceText = [
        event.reportingSecuritySystem,
        event.source,
        event.vendor,
        event.serviceSource,
        event.provider,
        event.category
    ].filter(Boolean).join(' ').toLowerCase();

    return /cloudflare|cloudflare one|cloudflare api|\bwarp\b|\bgateway\b/.test(sourceText)
        ? 'Cloudflare'
        : 'Microsoft Graph';
}

function getSunbirdSecurityApiCategory(event = {}) {
    if (event.rawPayload !== undefined) return event.category ?? 'Not provided';
    if (event.apiCategory) return event.apiCategory;
    if (event.recordType === 'alert') return event.categories?.join?.(', ') || event.category || event.classification || 'Not found';
    if (event.recordType === 'incident') return event.determination || event.classification || 'Not found';
    if (event.recordType === 'signin') return event.riskDetail || event.riskState || event.conditionalAccessStatus || 'Not found';
    if (event.recordType === 'indicator') return event.threatType || event.indicatorType || 'Not found';
    return event.cloudflareApiSignal ? (event.rawCategory || 'Not found') : 'Not found';
}

function getSunbirdSecurityDisplayTitle(event = {}) {
    const title = event.title || event.description || event.displayName || event.name || event.message || '';
    if (event.rawPayload !== undefined) return title || 'Not provided';
    if (!isSunbirdSecurityIdentifier(title)) return title || 'Security event';
    const description = String(event.description || '').trim();
    return description && !/^external threat indicator from microsoft graph$/i.test(description)
        ? description
        : 'Threat indicator';
}

function getSunbirdSecurityDisplayAsset(event = {}) {
    const asset = event.user || event.assignedTo || event.indicator || '';
    return asset && !isSunbirdSecurityIdentifier(asset) ? asset : 'Not found';
}

function isSunbirdSecurityIdentifier(value) {
    const text = String(value || '').trim();
    return /^[a-f0-9]{24,}$/i.test(text) || /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(text);
}

function renderSunbirdSecurityRawEvidenceHeader(model = buildSunbirdSecurityModel()) {
    const target = document.getElementById('sunbird-security-raw-evidence-header');
    if (!target) return;
    const rawEvidence = model.rawEvidence || {};
    const rawCount = Number(rawEvidence.displayedRecordCount ?? model.allEvents?.length ?? 0);
    const cloudflare = rawEvidence.cloudflare || {};
    const cloudflareStatus = String(cloudflare.status || 'not_reported').toLowerCase();
    const cloudflareCount = Number(cloudflare.rawRecordsReturned ?? cloudflare.recordsReturned ?? 0);
    const rawUpdatedAt = rawEvidence.rawEvidenceUpdatedAt;
    const evaluatedAt = rawEvidence.correlationEvaluatedAt;
    const awaitingEvaluation = rawEvidence.correlationStatus === 'awaiting_next_evaluation';
    const cloudflareCountText = cloudflareCount
        ? `${cloudflareCount} retained raw Cloudflare record${cloudflareCount === 1 ? '' : 's'}. `
        : '';
    const cloudflareMessage = cloudflareStatus === 'available' || cloudflareStatus === 'complete'
        ? (cloudflareCount ? `${cloudflareCountText}Cloudflare collection returned this evidence.` : 'Cloudflare collection completed; no raw Cloudflare alert was returned.')
        : cloudflareStatus === 'partial'
            ? `${cloudflareCountText}Cloudflare collection is partial. ${cloudflare.reason || 'Some Cloudflare evidence could not be collected.'}`
            : cloudflareStatus === 'unavailable'
                ? `${cloudflareCountText}Cloudflare collection is unavailable. ${cloudflare.reason || 'No Cloudflare result is being represented as a clean result.'}`
                : 'Cloudflare collection state was not reported by this snapshot.';
    const evaluationMessage = evaluatedAt
        ? `Last evaluated ${sunbirdSecurityFormatTime(evaluatedAt)}.${awaitingEvaluation ? ' New raw records are awaiting the next correlation and AI evaluation.' : ''}`
        : awaitingEvaluation
            ? 'Evaluation time not supplied. New raw records are awaiting the next correlation and AI evaluation.'
            : 'Evaluation time not supplied.';
    target.innerHTML = `
        <div class="sunbird-security-raw-evidence-title">
            <div><p class="sunbird-security-eyebrow">04 · provider ledger</p><h3>Raw provider evidence</h3><p>Individual Microsoft and Cloudflare records retained for review. They are not AI conclusions and are never sent directly to WhatsApp.</p></div>
            <span class="sunbird-security-raw-count">${sunbirdSecurityEscape(rawCount)} returned record${rawCount === 1 ? '' : 's'}</span>
        </div>
        <p>${[...(model.warnings || []), ...(model.retrieval?.limitations || [])].map(warning => sunbirdSecurityEscape(warning)).join(' ? ')}</p>
        <div class="sunbird-security-raw-statuses">
            <p><b>Cloudflare</b><span class="sunbird-security-status ${sunbirdSecurityStatusClass(cloudflareStatus)}">${sunbirdSecurityEscape(sunbirdSecurityStatusLabel(cloudflareStatus))}</span><small>${sunbirdSecurityEscape(cloudflareMessage)}</small></p>
            <p><b>Raw evidence updated</b><small>${sunbirdSecurityEscape(rawUpdatedAt ? sunbirdSecurityFormatTime(rawUpdatedAt) : 'Time not supplied')}</small></p>
            <p><b>Correlation / AI evaluated</b><small>${sunbirdSecurityEscape(evaluationMessage)}</small></p>
        </div>
        <details><summary>Retrieval health and coverage</summary><div style="overflow:auto"><table><thead><tr><th>Provider / dataset</th><th>State</th><th>Last attempt</th><th>Last complete</th><th>Records / pages</th><th>Failures / rate limits / permissions</th><th>Storage</th></tr></thead><tbody>${(model.retrieval?.sources || []).map(row => `<tr><td>${sunbirdSecurityEscape(row.provider)}<br>${sunbirdSecurityEscape(row.endpoint)}</td><td>${sunbirdSecurityEscape(row.status)}${row.resumable ? ' (will resume)' : ''}<br>${sunbirdSecurityEscape(row.error || row.limitation || '')}</td><td>${sunbirdSecurityEscape(sunbirdSecurityFormatTime(row.lastAttemptAt))}</td><td>${sunbirdSecurityEscape(sunbirdSecurityFormatTime(row.lastSuccessAt))}</td><td>${Number(row.recordsRetrieved || 0)} / ${Number(row.pages || 0)}</td><td>${Number(row.failedRequests || 0)} / ${Number(row.rateLimits || 0)} / ${Number(row.permissionErrors || 0)}</td><td>${sunbirdSecurityEscape(row.storageStatus || 'Not confirmed')} ${sunbirdSecurityEscape(row.storageError || '')}</td></tr>`).join('')}</tbody></table></div></details>`;
}

function renderSunbirdSecurityTable(model = buildSunbirdSecurityModel()) {
    renderSunbirdSecurityRawEvidenceHeader(model);
    const body = document.getElementById('sunbird-security-body');
    if (!body) return;
    const events = getFilteredSunbirdSecurityEvents(model);
    if (!events.length) {
        body.innerHTML = '<tr><td colspan="11" class="sunbird-id-empty">No SOC evidence matches the current filters.</td></tr>';
        return;
    }
    body.innerHTML = events.map(event => {
        const severity = event.sourceSeverity ?? event.severity ?? 'Not provided';
        const mitre = getSunbirdSecurityMitre(event);
        const apiSource = getSunbirdSecurityApiSource(event);
        const apiCategory = getSunbirdSecurityApiCategory(event);
        return `
            <tr>
                <td data-label="Time">${escapeIdentityText(sunbirdSecurityFormatTime(event.timestamp))}</td>
                <td data-label="Severity"><span class="sunbird-id-risk ${severity === 'critical' || severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'safe'}">${escapeIdentityText(severity)}</span></td>
                <td data-label="Type"><span class="sunbird-id-role-list"><span>${escapeIdentityText(event.recordType || 'event')}</span></span></td>
                <td data-label="Incident / Alert">${escapeIdentityText(getSunbirdSecurityDisplayTitle(event))}</td>
                <td data-label="Status"><span class="sunbird-id-pill">${escapeIdentityText(event.status ?? 'Not provided')}</span></td>
                <td data-label="User / Asset">${escapeIdentityText(getSunbirdSecurityDisplayAsset(event))}</td>
                <td data-label="Source">${escapeIdentityText(event.endpoint || apiSource)}</td>
                <td data-label="API Source">${escapeIdentityText(event.provider || getSunbirdSecurityReportingSystem(event))}</td>
                <td data-label="Category">${escapeIdentityText(apiCategory)}</td>
                <td data-label="MITRE">${escapeIdentityText(mitre.technique === 'Not provided' ? 'Not provided' : `${mitre.tactic} / ${mitre.technique}`)}</td>
                <td data-label="Evidence"><button type="button" class="sunbird-id-evidence-btn" onclick='openSunbirdSecurityEventEvidence(${escapeIdentityText(JSON.stringify(event.uid))})'>Open</button></td>
            </tr>
        `;
    }).join('');
}

function getFilteredSunbirdSecurityEvents(model = buildSunbirdSecurityModel()) {
    const search = sunbirdSecurityTableState.search.trim().toLowerCase();
    return model.allEvents.filter(event => {
        const severity = String(event.severity ?? 'Not provided').toLowerCase();
        const status = String(event.status || event.riskLevel || '').toLowerCase();
        const type = String(event.recordType || '').toLowerCase();
        const mitre = getSunbirdSecurityMitre(event);
        const haystack = [
            event.title, event.displayName, event.name, event.message, event.description,
            event.user, event.assignedTo, event.indicator, event.source, event.vendor,
            event.category, event.location, event.ipAddress, mitre.tactic, mitre.technique,
            severity, status, type
        ].join(' ').toLowerCase();
        if (search && !haystack.includes(search)) return false;
        if (sunbirdSecurityTableState.severity !== 'all' && severity !== sunbirdSecurityTableState.severity) return false;
        if (sunbirdSecurityTableState.status !== 'all' && status !== sunbirdSecurityTableState.status) return false;
        if (sunbirdSecurityTableState.source === 'cloudflare' && !/cloudflare/i.test([event.source, event.vendor, event.recordType, event.type].filter(Boolean).join(' '))) return false;
        if (sunbirdSecurityTableState.source !== 'all' && sunbirdSecurityTableState.source !== 'cloudflare' && type !== sunbirdSecurityTableState.source) return false;
        return true;
    }).sort((a, b) => {
        if (sunbirdSecurityTableState.sort === 'severity') return getSunbirdSecuritySeverityRank(b.severity) - getSunbirdSecuritySeverityRank(a.severity);
        if (sunbirdSecurityTableState.sort === 'status') return String(a.status || '').localeCompare(String(b.status || ''));
        return getSunbirdSecurityTime(b) - getSunbirdSecurityTime(a);
    });
}

function getSunbirdSecurityTime(item) {
    const raw = item?.timestamp || item?.created || item?.updated || item?.eventTime || item?.createdDateTime;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
}

function getSunbirdSecuritySeverityRank(value) {
    const severity = getSunbirdSecurityProviderSeverity(value);
    if (severity === 'critical') return 4;
    if (severity === 'high') return 3;
    if (severity === 'medium') return 2;
    if (severity === 'low') return 1;
    return 0;
}

function getSunbirdSecurityProviderSeverity(value) {
    const severity = String(value || '').trim().toLowerCase();
    return ['critical', 'high', 'medium', 'low'].includes(severity) ? severity : 'unassessed';
}

function openSunbirdSecurityEventEvidence(uid) {
    const model = buildSunbirdSecurityModel();
    const event = model.allEvents.find(item => item.uid === uid);
    if (!event) return;
    if (event.rawPayload !== undefined) {
        openSunbirdSecurityRowsModal(event.title || event.recordType, [{ title: event.provider, subtitle: event.endpoint, meta: 'Original provider JSON' }]);
        const list = document.querySelector('#sunbird-security-evidence-modal .sunbird-id-evidence-list');
        if (list) {
            const pre = document.createElement('pre');
            pre.style.cssText = 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto';
            pre.textContent = JSON.stringify(event.rawPayload, null, 2);
            list.appendChild(pre);
        }
        return;
    }
    const mitre = getSunbirdSecurityMitre(event);
    openSunbirdSecurityRowsModal(event.title || event.displayName || event.name || 'Security evidence', [{
        title: event.description || event.message || event.name || 'SOC evidence',
        subtitle: `${event.user || event.source || event.location || 'Microsoft Security'} | ${event.status || event.riskLevel || 'observed'}`,
        meta: `${formatSunbirdDateTime(event.timestamp)} | ${event.severity || 'low'} | ${mitre.tactic} / ${mitre.technique}`
    }]);
}

function openSunbirdSecurityRowsModal(title, rows) {
    const modal = document.getElementById('sunbird-security-evidence-modal');
    if (!modal) return;
    modal.innerHTML = `
        <div class="sunbird-id-modal-backdrop" onclick="closeSunbirdSecurityEvidence()"></div>
        <div class="sunbird-id-modal-panel" role="dialog" aria-modal="true">
            <div class="sunbird-id-modal-header">
                <div><h3>${escapeIdentityText(title)}</h3><p>${rows.length} evidence item${rows.length === 1 ? '' : 's'}.</p></div>
                <button type="button" onclick="closeSunbirdSecurityEvidence()" class="sunbird-id-modal-close">&times;</button>
            </div>
            <div class="sunbird-id-evidence-list">
                ${rows.map(row => `<div class="sunbird-id-evidence-user"><strong>${escapeIdentityText(row.title)}</strong><span>${escapeIdentityText(row.subtitle)}</span><small>${escapeIdentityText(row.meta)}</small></div>`).join('') || '<div class="sunbird-id-empty">No evidence found.</div>'}
            </div>
            <div class="sunbird-id-modal-actions"><button type="button" class="sunbird-id-evidence-btn" onclick="closeSunbirdSecurityEvidence()">Close</button></div>
        </div>
    `;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

function closeSunbirdSecurityEvidence() {
    const modal = document.getElementById('sunbird-security-evidence-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
}

async function fetchSunbirdSecurityEventsData({ onEvent, since, until } = {}) {
    const token = localStorage.getItem('authToken');
    if (!token) throw new Error('Authentication required');

    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
    let lastError;
    for (const endpoint of ['/api/security-events' + (onEvent ? '?stream=1' + (since ? '&since=' + encodeURIComponent(since) : '') + (until ? '&until=' + encodeURIComponent(until) : '') : '')]) {
        try {
            const response = await fetch(endpoint, { headers, cache: 'no-store' });
            if (onEvent && response.ok && response.body?.getReader) {
                const reader = response.body.getReader(), decoder = new TextDecoder();
                let buffer = '', completed = null;
                const consume = line => {
                    if (!line.trim()) return;
                    const event = JSON.parse(line);
                    onEvent(event);
                    if (event.type === 'error') throw new Error(event.message);
                    if (event.type === 'complete') completed = event.payload;
                };
                try {
                    while (true) {
                        const { value, done } = await reader.read();
                        buffer += decoder.decode(value, { stream: !done });
                        let end;
                        while ((end = buffer.indexOf('\n')) >= 0) { consume(buffer.slice(0, end)); buffer = buffer.slice(end + 1); }
                        if (done) break;
                    }
                    if (buffer.trim()) consume(buffer);
                } finally { reader.releaseLock(); }
                if (!completed) throw new Error('Provider collection disconnected before completion. Received records remain available.');
                return normalizeSunbirdSecurityData(completed);
            }
            const data = await response.json();
            if (response.ok && data.success) return normalizeSunbirdSecurityData(data);
            lastError = new Error(data.message || `Security events request failed (${response.status})`);
        } catch (error) {
            lastError = error;
        }
    }
    throw new Error(`Security events data unavailable: ${lastError?.message || 'both sources failed'}`);
}

function mergeSunbirdRawRecords(previous = [], incoming = []) {
    const rows = new Map(previous.map(row => [row.uid, row]));
    incoming.forEach(row => { const prior = rows.get(row.uid); if (!prior || (Number(row.providerVersion || 0) >= Number(prior.providerVersion || 0) && String(row.retrievedAt || '') >= String(prior.retrievedAt || '')) rows.set(row.uid, row); });
    return [...rows.values()];
}
localStorage.setItem('authToken','fixture-only');
fetchSunbirdSecurityEventsData({onEvent:event=>{if(event.type==='records'){model.rawRecords=mergeSunbirdRawRecords(model.rawRecords,event.records);model.allEvents=model.rawRecords;model.rawEvidence.displayedRecordCount=model.rawRecords.length;document.getElementById('state').textContent='Streaming '+model.rawRecords.length+' records';renderSunbirdSecurityTable(model)}}}).then(()=>document.getElementById('state').textContent='Collection complete').catch(error=>document.getElementById('state').textContent=error.message);
