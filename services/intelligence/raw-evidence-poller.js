// Each provider source runs independently: a slow history page or database never
// gates another source's next live poll. Provider collectors enforce deadlines.
function createRawEvidencePoller({ discover, sources, intervalMs = 30000, enabled = true, logger = console }) {
    const companies = new Set(), active = new Map();
    let timer, discovering, lastDiscovery = 0;
    function register(companyId) {
        if (Number.isInteger(Number(companyId)) && Number(companyId) > 0) companies.add(Number(companyId));
    }
    function runOnce() {
        if (!enabled) return [];
        if (!discovering && Date.now() - lastDiscovery >= 300000) {
            lastDiscovery = Date.now();
            discovering = Promise.resolve().then(discover).then(ids => ids.forEach(register))
                .catch(error => logger.warn('[Raw evidence] Tenant discovery:', error.message))
                .finally(() => { discovering = null; });
        }
        const pending = [];
        for (const companyId of companies) for (const [name, collect] of Object.entries(sources)) {
            const key = companyId + ':' + name;
            if (active.has(key)) { pending.push(active.get(key)); continue; }
            const task = Promise.resolve().then(() => collect(companyId))
                .catch(error => logger.warn('[Raw evidence] ' + name + ':', error.message))
                .finally(() => active.delete(key));
            active.set(key, task); pending.push(task);
        }
        return pending;
    }
    return { register, runOnce, start() {
        if (!enabled || timer) return;
        runOnce();
        timer = setInterval(runOnce, Math.max(10000, Number(intervalMs) || 30000));
        timer.unref?.();
    }, stop() { clearInterval(timer); timer = null; } };
}
module.exports = { createRawEvidencePoller };
