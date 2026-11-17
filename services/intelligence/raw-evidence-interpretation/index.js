const { interpretMicrosoft } = require('./microsoft');
const { interpretCloudflare } = require('./cloudflare');
const { base, first, readable } = require('./common');

function interpretRawEvidence(record, options = {}) {
    if (!record.rawPayload || typeof record.rawPayload !== 'object') return null;
    options = { platformTokenIds: String(process.env.SECURITY_CLOUDFLARE_PLATFORM_TOKEN_IDS || '').split(',').map(value => value.trim()).filter(Boolean), ...options };
    let presentation;
    try { presentation = record.provider === 'Microsoft Graph' ? interpretMicrosoft(record) : record.provider === 'Cloudflare' ? interpretCloudflare(record, options) : null; }
    catch { /* Preserve malformed or newly introduced provider schemas as unclassified evidence. */ }
    if (!presentation) {
        const raw = record.rawPayload, action = first(raw.action?.description, raw.action?.type, typeof raw.action === 'string' ? raw.action : '', raw.eventType, raw.type);
        presentation = { ...base(record, record.provider || 'Provider', readable(record.recordType), null, 'unclassified.v1'),
            title: `Unclassified activity${action ? ': ' + action : ''}`, action,
            description: first(raw.description, raw.message) || 'The provider returned a record without enough supported context to interpret the activity.',
            securitySignificance: 'Security significance cannot be established from the supported fields in this record.' };
    }
    presentation.sections = presentation.sections.filter(section => section.fields.length);
    return presentation;
}
// The original envelope stays available for storage and technical inspection.
function presentRawEvidence(record) {
    const { rawPayload, ...compact } = record;
    return { ...compact, presentation: record.presentation || interpretRawEvidence(record), technicalAvailable: true };
}
module.exports = { interpretRawEvidence, presentRawEvidence };
