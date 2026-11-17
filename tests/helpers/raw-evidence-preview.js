// Local browser QA only. No provider credentials, database access or production startup.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { rawSecurityRecord } = require('../../services/intelligence/raw-security-records');
const { presentRawEvidence } = require('../../services/intelligence/raw-evidence-interpretation');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'js/clientportal.js'), 'utf8');
const names = ['escapeIdentityText', 'sunbirdSecurityDisplayText', 'sunbirdSecurityEscape', 'sunbirdSecurityStatusClass', 'sunbirdSecurityStatusLabel',
    'sunbirdSecurityFormatTime', 'getSunbirdSecurityMitre', 'getSunbirdSecurityApiSource', 'getSunbirdSecurityReportingSystem',
    'getSunbirdSecurityApiCategory', 'getSunbirdSecurityDisplayTitle', 'getSunbirdSecurityDisplayAsset', 'isSunbirdSecurityIdentifier',
    'renderSunbirdSecurityRawEvidenceHeader', 'renderSunbirdSecurityTable', 'getFilteredSunbirdSecurityEvents', 'getSunbirdSecurityTime',
    'getSunbirdSecuritySeverityRank', 'getSunbirdSecurityProviderSeverity', 'openSunbirdSecurityEventEvidence', 'openSunbirdSecurityRowsModal',
    'closeSunbirdSecurityEvidence', 'fetchSunbirdSecurityEventsData', 'mergeSunbirdRawRecords', 'renderSunbirdRawEvidenceDetails', 'loadSunbirdRawTechnicalEvidence', 'applySunbirdSecurityTableFilter'];
const code = names.map(name => {
    const match = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
    if (!match) throw new Error('Missing function ' + name);
    const rest = source.slice(match.index), next = /\n(?:async )?function /.exec(rest.slice(1));
    return next ? rest.slice(0, next.index + 1) : rest;
}).join('\n');
const rows = [
    rawSecurityRecord({ id: 'graph-one', createdDateTime: '2026-11-17T10:12:34Z', userDisplayName: 'Gary Norton', appDisplayName: 'Microsoft Loop App', location: { city: 'Wincanton', countryOrRegion: 'United Kingdom' }, ipAddress: '89.240.195.214', userPrincipalName: 'fixture@example.test', status: { errorCode: 0, failureReason: 'Other.', additionalDetails: 'MFA requirement satisfied by claim in the token' } }, { companyId: 11, provider: 'Microsoft Graph', endpoint: '/v1.0/auditLogs/signIns', recordType: 'signin', retrievedAt: '2026-11-17T10:13:00Z' }),
    rawSecurityRecord({ rayName: 'cf-one', action: 'block', source: 'waf', datetime: '2026-11-17T10:12:35Z', clientIP: '203.0.113.5', description: '<script>window.injected=true</script>' }, { companyId: 11, provider: 'Cloudflare', endpoint: '/graphql/firewallEventsAdaptive/fixture-zone', recordType: 'firewall_event', retrievedAt: '2026-11-17T10:13:00Z' })
];
const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/css/clientportal.css"><style>body{background:#101419;color:#eee;font:14px Arial;padding:24px}table{border-collapse:collapse;width:100%}td,th{padding:12px;border-bottom:1px solid #444;text-align:left}button{padding:8px;cursor:pointer}#sunbird-security-evidence-modal{display:none}#sunbird-security-evidence-modal.open{display:block;position:fixed;inset:10%;background:#202a35;padding:20px;overflow:auto}.table-scroll{overflow:auto}pre{color:#fff}</style></head><body><h1>Raw evidence browser QA — fixtures only</h1><p id="state">Connecting</p><div id="sunbird-security-dashboard"><header id="sunbird-security-raw-evidence-header"></header><div class="table-scroll"><table><thead><tr>${['Time','Severity','Type','Incident / Alert','Status','User / Asset','Source','API Source','Category','MITRE','Evidence'].map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody id="sunbird-security-body"></tbody></table></div></div><div id="sunbird-security-evidence-modal"></div><script>
const sunbirdSecurityTableState={search:'',severity:'all',status:'all',source:'all',sort:'newest'};
let model={rawRecords:[],allEvents:[],rawEvidence:{},warnings:[],retrieval:{sources:[]}};
function buildSunbirdSecurityModel(){return model} function normalizeSunbirdSecurityData(data){return data}
${code}
localStorage.setItem('authToken','fixture-only');
fetchSunbirdSecurityEventsData({onEvent:event=>{if(event.type==='records'){model.rawRecords=mergeSunbirdRawRecords(model.rawRecords,event.records);model.allEvents=model.rawRecords;model.rawEvidence.displayedRecordCount=model.rawRecords.length;document.getElementById('state').textContent='Streaming '+model.rawRecords.length+' records';renderSunbirdSecurityTable(model)}}}).then(()=>document.getElementById('state').textContent='Collection complete').catch(error=>document.getElementById('state').textContent=error.message);
</script></body></html>`;
http.createServer((req,res) => {
    if (req.url.startsWith('/api/security-events/record')) {
        res.setHeader('Content-Type', 'application/json');
        const uid = new URL(req.url, 'http://localhost').searchParams.get('uid');
        res.end(JSON.stringify({ success: true, record: rows.find(row => row.uid === uid) }));
    } else if (req.url.startsWith('/api/security-events')) {
        res.setHeader('Content-Type','application/x-ndjson');
        res.write(JSON.stringify({type:'records',records:[presentRawEvidence(rows[0])]})+'\n');
        setTimeout(()=>res.write(JSON.stringify({type:'records',records:[presentRawEvidence(rows[1])]})+'\n'),300);
        setTimeout(()=>res.end(JSON.stringify({type:'complete',payload:{success:true,rawRecords:rows.map(presentRawEvidence)}})+'\n'),1500);
    } else if (req.url === '/css/clientportal.css') {
        res.setHeader('Content-Type','text/css');
        const css = path.join(root,'css/clientportal.css');
        res.end(fs.existsSync(css) ? fs.readFileSync(css) : '');
    } else { res.setHeader('Content-Type','text/html'); res.end(html); }
}).listen(4193, '127.0.0.1', () => console.log('Raw evidence QA: http://127.0.0.1:4193'));
