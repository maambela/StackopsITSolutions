const scalar = value => ['string', 'number', 'boolean'].includes(typeof value) ? String(value).trim() : '';
const meaningful = value => { const text = scalar(value); return /^(other[.]?|unknown|unknownFutureValue|n\/a|none|null)$/i.test(text) ? '' : text; };
const first = (...values) => values.map(meaningful).find(Boolean) || '';
const readable = value => scalar(value).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ');
const fields = entries => entries.filter(([, value]) => value !== null && value !== undefined && scalar(value) !== '').map(([label, value]) => ({ label, value: scalar(value) }));
const section = (title, entries) => ({ title, fields: fields(entries) });
const list = values => Array.isArray(values) ? values.map(meaningful).filter(Boolean).join(', ') : meaningful(values);
const location = value => value && typeof value === 'object' ? [value.city, value.state, value.countryOrRegion || value.country].map(meaningful).filter((part, index, all) => part && all.indexOf(part) === index).join(', ') : meaningful(value);
function base(record, sourceLabel, dataset, category, ruleId) {
    const raw = record.rawPayload || {};
    const providerCategory = first(raw.category, list(raw.categories));
    return { version: 1, ruleId, sourceLabel, dataset, title: '', description: '', actor: '', asset: '', action: '', outcome: '',
        category: providerCategory || category || 'Unclassified', categoryBasis: providerCategory ? 'Provider category' : category ? 'Provider dataset and event schema' : 'Insufficient classification evidence',
        activityClass: 'unclassified', routine: false, securitySignificance: '', sections: [],
        mitreTechniques: Array.isArray(raw.mitreTechniques) ? raw.mitreTechniques.filter(value => typeof value === 'string') : [],
        mitreBasis: Array.isArray(raw.mitreTechniques) && raw.mitreTechniques.length ? 'Provider supplied' : 'No validated mapping for this record' };
}
module.exports = { scalar, meaningful, first, readable, section, list, location, base };
