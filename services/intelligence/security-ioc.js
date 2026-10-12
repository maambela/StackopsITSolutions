const net = require('node:net');

const IOC_FIELDS = [
    ['IPAddress', ['ipAddress', 'clientIpAddress', 'sourceIpAddress', 'ip']],
    ['URL', ['url', 'uri', 'link', 'maliciousUrl']],
    ['Domain', ['maliciousDomain', 'senderDomain', 'urlDomain']],
    ['FileHash', ['fileHash', 'sha256', 'sha1', 'md5']],
    ['SenderAddress', ['senderAddress', 'senderEmail', 'fromAddress']]
];

function normalizeIoc(type, value) {
    if (typeof value !== 'string' && typeof value !== 'number') return null;
    const text = String(value).trim().replace(/[),.;]+$/g, '');
    if (!text || text.length > 500) return null;

    if (type === 'IPAddress') return net.isIP(text) ? text : null;
    if (type === 'URL') {
        try {
            const url = new URL(text);
            return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null;
        } catch {
            return null;
        }
    }
    if (type === 'Domain') {
        const domain = text.toLowerCase().replace(/\.$/, '');
        return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
            ? domain
            : null;
    }
    if (type === 'FileHash') {
        return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(text) ? text.toLowerCase() : null;
    }
    if (type === 'SenderAddress') {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text) ? text.toLowerCase() : null;
    }
    return null;
}

function getExplicitSecurityIocs(record = {}) {
    if (!record || typeof record !== 'object') return [];
    const found = new Map();
    for (const [type, fields] of IOC_FIELDS) {
        for (const field of fields) {
            const value = normalizeIoc(type, record[field]);
            if (!value) continue;
            const key = `${type}:${value}`.toLowerCase();
            if (!found.has(key)) found.set(key, { type, value, sourceField: field });
        }
    }
    return [...found.values()];
}

function getMicrosoftThreatIndicatorIocs(indicator = {}) {
    if (!indicator || typeof indicator !== 'object') return [];
    const candidates = [
        ['IPAddress', 'IPAddress', indicator.networkIPv4],
        ['IPAddress', 'IPAddress', indicator.networkIPv6],
        ['Domain', 'Domain', indicator.domainName],
        ['URL', 'URL', indicator.url],
        ['FileHash', 'FileHash', indicator.fileHashValue],
        ['SenderAddress', 'SenderAddress', indicator.emailSender]
    ];
    const found = new Map();
    for (const [type, validationType, candidate] of candidates) {
        const value = normalizeIoc(validationType, candidate);
        if (value) found.set(`${type}:${value}`.toLowerCase(), { type, value });
    }
    return [...found.values()];
}

function normalizeTypedSecurityIoc(type, value) {
    const normalizedType = String(type || '').toLowerCase().replace(/[^a-z]/g, '');
    const typeMap = new Map([
        ['ip', 'IPAddress'],
        ['ipaddress', 'IPAddress'],
        ['ipv4', 'IPAddress'],
        ['ipv6', 'IPAddress'],
        ['url', 'URL'],
        ['uri', 'URL'],
        ['domain', 'Domain'],
        ['domainname', 'Domain'],
        ['filehash', 'FileHash'],
        ['sha256', 'FileHash'],
        ['sha1', 'FileHash'],
        ['md5', 'FileHash'],
        ['senderaddress', 'SenderAddress']
    ]);
    const canonicalType = typeMap.get(normalizedType);
    const normalizedValue = canonicalType ? normalizeIoc(canonicalType, value) : null;
    return normalizedValue ? { type: canonicalType, value: normalizedValue } : null;
}

module.exports = {
    getExplicitSecurityIocs,
    normalizeIoc,
    getMicrosoftThreatIndicatorIocs,
    normalizeTypedSecurityIoc
};
