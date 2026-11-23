const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const {
    createApplicationCollectionCoordinator
} = require('../services/intelligence/application-collection-coordinator');

test('complete application payload is reused within the TTL', async () => {
    let calls = 0;
    let now = 1000;
    const coordinator = createApplicationCollectionCoordinator({
        payloadTtlMs: 60000,
        now: () => now
    });
    const payload = { success: true, applications: [{ id: 'app-1' }], summary: { totalApplications: 1 } };

    const first = await coordinator.runPayload('company:1', async () => {
        calls++;
        return payload;
    });
    now += 30000;
    const second = await coordinator.runPayload('company:1', async () => {
        calls++;
        throw new Error('should not run');
    });

    assert.equal(first, payload);
    assert.equal(second, payload);
    assert.equal(calls, 1);
});

test('default payload and assignment reuse lasts 15 and 60 minutes', async () => {
    let now = 1000;
    let payloadCalls = 0;
    let assignmentCalls = 0;
    const coordinator = createApplicationCollectionCoordinator({ now: () => now });
    const payload = { success: true, applications: [{ id: 'app-1' }] };

    await coordinator.runPayload('company:1', async () => {
        payloadCalls++;
        return payload;
    });
    now += 15 * 60 * 1000 - 1;
    assert.equal(await coordinator.runPayload('company:1', async () => {
        payloadCalls++;
        return payload;
    }), payload);
    now++;
    await coordinator.runPayload('company:1', async () => {
        payloadCalls++;
        return payload;
    });

    const assignments = [{ principalType: 'User' }];
    await coordinator.runAssignment('tenant:A:app-1', async () => {
        assignmentCalls++;
        return assignments;
    });
    now += 60 * 60 * 1000 - 1;
    assert.equal(await coordinator.runAssignment('tenant:A:app-1', async () => {
        assignmentCalls++;
        return assignments;
    }), assignments);
    now++;
    await coordinator.runAssignment('tenant:A:app-1', async () => {
        assignmentCalls++;
        return assignments;
    });

    assert.equal(payloadCalls, 2);
    assert.equal(assignmentCalls, 2);
});

test('failed or incomplete application payloads are not cached', async () => {
    let calls = 0;
    const coordinator = createApplicationCollectionCoordinator({ payloadTtlMs: 60000 });

    await coordinator.runPayload('company:1', async () => {
        calls++;
        return { success: false, applications: [] };
    });
    await coordinator.runPayload('company:1', async () => {
        calls++;
        return { success: true, applications: [{ id: 'app-1' }] };
    });

    assert.equal(calls, 2);
});

test('assignment collections join overlapping work and stay isolated by tenant scope', async () => {
    let tenantACalls = 0;
    let tenantBCalls = 0;
    const coordinator = createApplicationCollectionCoordinator({ assignmentTtlMs: 60000 });

    const [first, joined] = await Promise.all([
        coordinator.runAssignment('tenant:A:app-1', async () => {
            tenantACalls++;
            await new Promise(resolve => setTimeout(resolve, 5));
            return [{ principalType: 'User' }];
        }),
        coordinator.runAssignment('tenant:A:app-1', async () => {
            tenantACalls++;
            return [{ principalType: 'Group' }];
        })
    ]);
    const tenantB = await coordinator.runAssignment('tenant:B:app-1', async () => {
        tenantBCalls++;
        return [];
    });

    assert.equal(tenantACalls, 1);
    assert.deepEqual(first, [{ principalType: 'User' }]);
    assert.equal(joined, first);
    assert.equal(tenantBCalls, 1);
    assert.deepEqual(tenantB, []);
});

test('overlapping application payload requests join the in-flight collection', async () => {
    let calls = 0;
    let resolvePayload;
    const coordinator = createApplicationCollectionCoordinator();
    const first = coordinator.runPayload('company:1', () => {
        calls++;
        return new Promise(resolve => { resolvePayload = resolve; });
    });
    const joined = coordinator.runPayload('company:1', async () => {
        calls++;
        return { success: true, applications: [] };
    });

    await new Promise(resolve => setImmediate(resolve));
    resolvePayload({ success: true, applications: [{ id: 'app-1' }] });
    const [firstPayload, joinedPayload] = await Promise.all([first, joined]);

    assert.equal(calls, 1);
    assert.equal(joinedPayload, firstPayload);
});

test('forced payload and assignment refreshes bypass recent completed results', async () => {
    let payloadCalls = 0;
    let assignmentCalls = 0;
    const coordinator = createApplicationCollectionCoordinator();

    await coordinator.runPayload('company:1', async () => {
        payloadCalls++;
        return { success: true, applications: [{ id: 'old' }] };
    });
    const payload = await coordinator.runPayload('company:1', async () => {
        payloadCalls++;
        return { success: true, applications: [{ id: 'new' }] };
    }, { forceRefresh: true });

    await coordinator.runAssignment('tenant:A:app-1', async () => {
        assignmentCalls++;
        return [{ principalType: 'User' }];
    });
    await coordinator.runAssignment('tenant:A:app-1', async () => {
        assignmentCalls++;
        return [{ principalType: 'Group' }];
    }, { forceRefresh: true });

    assert.equal(payloadCalls, 2);
    assert.equal(payload.applications[0].id, 'new');
    assert.equal(assignmentCalls, 2);
});

test('server applications refresh reuses shared database freshness and explicit enterprise refresh bypasses payload reuse', () => {
    const source = fs.readFileSync('server.js', 'utf8');
    assert.match(source, /applications_cache_refresh_skipped_recent_complete/);
    assert.match(source, /cachedAgeMs\s*<\s*15\s*\*\s*60\s*\*\s*1000/);
    assert.match(source, /fetchApplicationsPayloadFromApi\(null,\s*\{\s*companyId,\s*tenantKey:\s*`company:\$\{companyId\}`,\s*forceRefresh:\s*true\s*\}\)/);
});
