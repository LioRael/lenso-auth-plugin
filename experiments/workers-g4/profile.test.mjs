import test from 'node:test';
import assert from 'node:assert/strict';
import { counters, observeDatabase, distribution } from './profile-observations.mjs';

test('nearest rank distributions include every sample and do not mutate input', () => {
  const input = [100, 1, 20, 2, 3];
  assert.deepEqual(distribution(input), { n: 5, min: 1, p50: 3, p95: 100, p99: 100, max: 100 });
  assert.deepEqual(input, [100, 1, 20, 2, 3]);
  assert.equal(distribution(Array.from({ length: 100 }, (_, i) => i + 1)).p95, 95);
  for (const bad of [[], [-1], [NaN], [Infinity]]) assert.throws(() => distribution(bad));
});

test('instrumentation forwards the exact primary batch, binds and response', async () => {
  const statements = [{ opaque: 'statement' }];
  const result = [{ results: [{ id: 1 }], meta: { rows_read: 12, rows_written: 2 } }];
  const counter = counters();
  let observed = 0;
  const db = observeDatabase({
    prepare(sql) { return { bind: (...params) => ({ sql, params }) }; },
    async batch(input) { assert.equal(input, statements); return result; },
    withSession() { assert.fail('Sessions must never be used'); },
  }, counter, { memory: () => observed++ });
  assert.deepEqual(db.prepare('select ?').bind(3), { sql: 'select ?', params: [3] });
  assert.equal(await db.batch(statements), result);
  assert.deepEqual(counter, { calls: 1, statements: 1, returned_rows: 1, rows_read: 12, rows_written: 2, failures: 0 });
  assert.equal(observed, 2);
});

test('unavailable D1 row metadata stays null across subsequent results', async () => {
  const counter = counters();
  const db = observeDatabase({ prepare() {}, async batch() { return [{ results: [] }, { results: [], meta: { rows_read: 7, rows_written: 0 } }]; } }, counter);
  await db.batch([{}, {}]);
  assert.equal(counter.rows_read, null);
  assert.equal(counter.rows_written, null);
});

test('controlled failure records an attempt without calling native storage', async () => {
  const counter = counters();
  const db = observeDatabase({ prepare() {}, batch() { assert.fail('fault must precede I/O'); } }, counter, { fail: true });
  await assert.rejects(db.batch([{}]), /injected storage failure/);
  assert.equal(counter.calls, 1);
  assert.equal(counter.failures, 1);
});

test('real batch rejection is counted and never retried or rewritten', async () => {
  const counter = counters(), failure = new Error('private upstream error');
  let calls = 0;
  const db = observeDatabase({ prepare() {}, batch() { calls++; throw failure; } }, counter);
  await assert.rejects(db.batch([{}, {}]), error => error === failure);
  assert.equal(calls, 1);
  assert.equal(counter.failures, 1);
});

test('local entry point uses the actual runner JSON contract and recovers after faults', async () => {
  // Stub only Wasm/D1 for this JS wiring test. This is not workerd evidence.
  const { createRequire } = await import('node:module');
  const { fileURLToPath } = await import('node:url');
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const { build } = wranglerRequire('esbuild');
  const bundle = await build({ entryPoints: [fileURLToPath(new URL('profile-worker.mjs', import.meta.url))],
    write: false, bundle: true, format: 'esm', platform: 'browser',
    plugins: [{ name: 'unit-wasm', setup(b) {
      b.onResolve({ filter: /lenso_workers_g4_host\.(js|wasm)$|lenso_workers_g4_host_bg\.wasm$/ }, args => ({ path: args.path, namespace: 'stub' }));
      b.onLoad({ filter: /.*/, namespace: 'stub' }, args => ({ contents: args.path.endsWith('.wasm') ? 'export default {};' : `
        export function initSync() { return { memory: new WebAssembly.Memory({ initial: 1 }), __wasm_call_ctors() {} }; }
        export function __wbg_reset_state() {}
        export async function migrate(owner, action, batch) { await batch('[{"sql":"SELECT 1","params":[]}]'); }
        export async function profile_invoke(input, scope) {
          await scope.accountBatch('[{"sql":"SELECT 1","params":[]}]');
          return JSON.stringify({ready:true, shutdown:'clean', outcome:{Ok:{owners:JSON.parse(input).owners}}});
        }` }));
    } }],
  });
  const { default: worker } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`);
  let batches = 0;
  const env = { SECRETS: {}, ACCOUNT_DB: {
    prepare(sql) { return { bind: (...params) => ({ sql, params }) }; },
    async batch() { batches++; return [{ results: [{ value: 1 }], meta: { rows_read: 1, rows_written: 0 } }]; },
  } };
  const call = async (operation, fault) => {
    const response = await worker.fetch(new Request('http://local/', { method: 'POST', body: JSON.stringify({ owners: 1, operation, request: {}, fault }) }), env);
    return { status: response.status, ...(await response.json()) };
  };
  assert.equal((await call('setup')).result.setup, true);
  const ready = await call('ready');
  assert.equal(ready.status, 200);
  assert.equal(ready.result.ready, true);
  assert.equal(ready.observations.d1.account.calls, 1);
  for (const fault of ['storage', 'abandon']) {
    const before = batches, failed = await call('ready', fault);
    assert.equal(failed.status, 503);
    assert.equal(failed.result.runtime_failure, true);
    assert.equal(batches, before);
    assert.ok(failed.observations.generation_after > failed.observations.generation_before);
    assert.equal((await call('ready')).status, 200);
  }
});
