const { performance } = require('node:perf_hooks');

function createGraphCoordinator({ concurrency = 6, maxQueued = 64 } = {}) {
    let active = 0;
    const pending = new Set();

    function drain() {
        while (active < concurrency && pending.size) {
            const entry = pending.values().next().value;
            pending.delete(entry);
            entry.signal.removeEventListener('abort', entry.abort);
            active++;
            entry.resolve(() => {
                active--;
                drain();
            });
        }
    }

    async function run(signal, operation) {
        signal.throwIfAborted();
        if (active >= concurrency && pending.size >= maxQueued) {
            const error = new Error('Microsoft Graph request queue is full');
            error.code = 'GRAPH_QUEUE_FULL';
            throw error;
        }
        const queuedAt = performance.now();
        const release = await new Promise((resolve, reject) => {
            const entry = { signal, resolve, abort() {
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
