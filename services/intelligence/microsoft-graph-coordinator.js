const { performance } = require('node:perf_hooks');

function createGraphCoordinator({ concurrency = 6, maxQueued = 64 } = {}) {
    let active = 0;
    let yieldToOldest = false;
    const pending = new Set();

    function drain() {
        while (active < concurrency && pending.size) {
            const oldest = pending.values().next().value;
            const preferred = !yieldToOldest && [...pending].find(entry => entry.preferDispatch);
            const entry = preferred || oldest;
            yieldToOldest = entry !== oldest;
            pending.delete(entry);
            entry.signal.removeEventListener('abort', entry.abort);
            active++;
            entry.resolve(() => {
                active--;
                drain();
            });
        }
    }

    async function run(signal, operation, { preferDispatch = false } = {}) {
        signal.throwIfAborted();
        if (active >= concurrency && pending.size >= maxQueued) {
            const error = new Error('Microsoft Graph request queue is full');
            error.code = 'GRAPH_QUEUE_FULL';
            throw error;
        }
        const queuedAt = performance.now();
        const release = await new Promise((resolve, reject) => {
            const entry = { signal, resolve, preferDispatch, abort() {
                pending.delete(entry);
                reject(signal.reason);
            } };
            pending.add(entry);
            signal.addEventListener('abort', entry.abort, { once: true });
            drain();
        });
        try {
            signal.throwIfAborted();
            return await operation(performance.now() - queuedAt);
        } finally {
            release();
        }
    }

    return { run };
}

const graphCoordinator = createGraphCoordinator();

module.exports = { createGraphCoordinator, graphCoordinator };
