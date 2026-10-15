const net = require('node:net');

const IP_FIELDS = ['ipAddress', 'clientIpAddress', 'sourceIpAddress', 'ip', 'networkIpAddress'];
const USER_FIELDS = ['userPrincipalName', 'userAccountName', 'accountUpn', 'accountName', 'userEmail', 'email'];
const DEVICE_FIELDS = ['deviceName', 'hostName', 'hostname', 'machineName', 'computerName'];
const MAX_DEPTH = 5;
const MAX_NODES = 300;

function cleanText(value) {
    return typeof value === 'string' || typeof value === 'number'
        ? String(value).trim()
        : '';
}

function cleanIp(value) {
    const candidate = cleanText(value).replace(/^\[|\]$/g, '');
    return net.isIP(candidate) ? candidate : '';
}

function unique(values) {
    return [...new Set(values.filter(Boolean))];
}

function collectKnownValues(record, fields, normalizer = cleanText) {
    if (!record || typeof record !== 'object') return [];

    const values = [];
    const queue = [{ value: record, depth: 0 }];
    let inspected = 0;
    while (queue.length && inspected < MAX_NODES) {
        const current = queue.shift();
        const value = current?.value;
        if (!value || typeof value !== 'object') continue;
        inspected += 1;

        for (const field of fields) {
            const candidate = normalizer(value[field]);
            if (candidate) values.push(candidate);
        }
        if (current.depth >= MAX_DEPTH) continue;

        for (const child of Object.values(value)) {
            if (child && typeof child === 'object') {
                if (Array.isArray(child)) {
                    child.slice(0, MAX_NODES).forEach(item => queue.push({ value: item, depth: current.depth + 1 }));
                } else {
                    queue.push({ value: child, depth: current.depth + 1 });
                }
            }
        }
    }
    return unique(values);
}

/**
 * Graph security alerts often put entities in `evidence`, not on the alert's
 * top level. Only explicit typed fields are used; alert text is never parsed.
 */
function extractMicrosoftAlertEntities(alert = {}) {
    const ipAddresses = collectKnownValues(alert, IP_FIELDS, cleanIp);
    const users = collectKnownValues(alert, USER_FIELDS).filter(value => !/^unknown(?: user)?$/i.test(value));
    const devices = collectKnownValues(alert, DEVICE_FIELDS).filter(value => !/^unknown(?: device)?$/i.test(value));

    return {
        ipAddresses,
        ipAddress: ipAddresses[0] || null,
        users,
        userPrincipalName: users[0] || null,
        devices,
        deviceName: devices[0] || null
    };
}

module.exports = { extractMicrosoftAlertEntities };
