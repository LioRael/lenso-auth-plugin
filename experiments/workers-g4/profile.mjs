#!/usr/bin/env node
// External, serial, local HTTP wall measurements. No Worker clock is sampled.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { cpus, platform, arch, release, totalmem, tmpdir } from 'node:os';
import { mkdtemp, readFile, writeFile, rm, copyFile, realpath } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { distribution } from './profile-observations.mjs';

const root = fileURLToPath(new URL('.', import.meta.url));
const repo = resolve(root, '../..');
const require = createRequire(import.meta.url);
const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
const { Miniflare } = wranglerRequire('miniflare');
const { build } = wranglerRequire('esbuild');
const artifactDir = resolve(process.env.G4_PROFILE_ARTIFACT_DIR || `${root}/pkg`);
const output = resolve(process.argv[2] || `${repo}/docs/workers-g4-d01.json`);
const samples = 30, coldSamples = 5;
const owners = ['account', 'oauth-flow', 'password', 'phone', 'device', 'api-token', 'oidc'];
const bindings = ['ACCOUNT_DB', 'OAUTH_DB', 'PASSWORD_DB', 'PHONE_DB', 'DEVICE_DB', 'API_TOKEN_DB', 'OIDC_DB'];
const expected = [
  'cold_ready_1', 'cold_ready_7', 'warm_ready_1', 'warm_ready_7',
  'password_valid', 'password_invalid', 'password_absent', 'api_issue', 'api_verify',
  'oidc_activation_probe', 'storage_failure', 'storage_recovery', 'abandonment', 'abandonment_recovery',
];
const evidence = {
  schema_version: 1, task: 'D01', status: 'running', started_at: new Date().toISOString(),
  configuration: { samples, cold_samples: coldSamples, concurrency: 1, compatibility_date: '2026-07-01',
    event_limit_ms: 15000, owner_sets: { 1: ['account'], 7: owners },
    argon2: { algorithm: 'argon2id', version: 19, memory_kib: 19456, iterations: 2, lanes: 1, output_bytes: 32 },
    percentile_estimator: 'nearest rank: sorted[ceil(p*n)-1]',
    warmup: 'One Ready per warm process, one register, one API issue; setup and warmups excluded.',
    sequence: '1-owner cold then warm; 7-owner cold then warm; each operation loop serial in listed order. Valid login resets throttling before each wrong-password sample.',
  },
  boundaries: {
    scope: 'local workerd, synthetic credentials, task-owned primary D1 SQLite databases',
    timing: 'External Node process.hrtime.bigint from before fetch to fully consumed response body; includes local HTTP, JSON, fresh App resolution/activation, operation, shutdown, instrumentation. Cold starts begin before Miniflare construction and include workerd launch/artifact loading.',
    cold: 'New workerd process and Wasm instance using the same release artifact and initialized D1 files; OS page/filesystem caches are not flushed. Build, key generation and schema setup excluded.',
    warm: 'Existing workerd isolate, fresh App and event storage scope for every request. Runner generation numbers expose normal retirement/reset; rotation samples are retained and counted.',
    memory: 'Wasm memory.buffer.byteLength at event entry, D1 boundaries and completion; allocated linear memory, not live heap, RSS or CPU. Within-generation memory does not shrink, so growth during synchronous Argon2 remains observable at return. Boundary samples are not a full peak profiler.',
    d1: 'Owner batch attempts and statement counts; returned rows separate from optional local result.meta rows_read/rows_written. No D1 duration is used as CPU. Failed batches may have unknown committed work. Setup/control-plane queries excluded.',
    oidc: 'Real OIDC Provider activation including unchanged RSA key-match validation, then metadata and public JWKS probes. No external IdP exchange, browser login or cloud egress is measured.',
    exclusions: ['CPU measurements', 'production capacity', 'throughput under load', 'SLA', 'external IdP qualification', 'cloud cost', 'constant-time proof'],
    statistics: 'Descriptive small samples: p99 is the maximum for n=30 and n=5. No confidence interval or cross-machine performance claim.',
  },
  environment: { platform: platform(), arch: arch(), os_release: release(), cpu: cpus()[0]?.model,
    logical_cpus: cpus().length, total_memory_bytes: totalmem(), node: process.version },
  identities: {}, scenarios: Object.fromEntries(expected.map(name => [name, {
    sample_count: 0, wall_ms: null, failure_counts: { unexpected: 0, domain: 0, runtime: 0 }, samples: [],
  }])),
  cleanup: { resources_removed: false, processes_disposed: false },
};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const command = (exe, args) => execFileSync(exe, args, { cwd: repo, encoding: 'utf8' }).trim();
let temp, active, stage = 'identities', processNumber = 0;
const interrupted = new AbortController();
const stop = () => interrupted.abort();
process.on('SIGINT', stop); process.on('SIGTERM', stop);
try {
  assert.equal(process.version, 'v26.8.2', 'D01 requires Node 26.8.2');
  const tools = {};
  for (const [name, version] of Object.entries({ wrangler: '4.107.0', miniflare: '4.20260701.0', workerd: '1.20260701.1', esbuild: '0.28.1' })) {
    tools[name] = wranglerRequire(`${name}/package.json`).version;
    assert.equal(tools[name], version, `Pinned ${name}`);
  }
  for (const [name, version] of Object.entries({ '@lenso/workers-runtime': '0.1.2', '@lenso/http-egress-workers': '0.1.0' })) {
    const file = resolve(dirname(require.resolve(name)), 'package.json');
    tools[name] = JSON.parse(await readFile(file)).version;
    assert.equal(tools[name], version, `Pinned ${name}`);
  }
  tools.rustc = command('rustc', ['+1.94.0', '-Vv']);
  const sharedCargo = '/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo';
  const cargo = process.env.CARGO || (existsSync(sharedCargo) ? sharedCargo : 'cargo');
  tools.cargo = command(cargo, ['+1.94.0', '-V']);
  tools.wasm_bindgen = command('wasm-bindgen', ['--version']);
  tools.pnpm = command('pnpm', ['--version']);
  tools.python = command('python3', ['--version']);
  assert.equal(tools.wasm_bindgen, 'wasm-bindgen 0.2.127');
  assert.equal(tools.pnpm, '11.5.0');
  const hashes = {};
  // Tracked build inputs plus task additions; evidence and generated output excluded.
  const files = command('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean);
  for (const file of files.sort()) {
    if (file.startsWith('docs/') || file.includes('/evidence/') || file.includes('/pkg/') || file.endsWith('.bundle.mjs')) continue;
    hashes[file] = sha(await readFile(resolve(repo, file)));
  }
  const artifacts = {};
  for (const name of ['lenso_workers_g4_host.js', 'lenso_workers_g4_host_bg.wasm']) {
    const bytes = await readFile(resolve(artifactDir, name));
    artifacts[name] = { sha256: sha(bytes), bytes: bytes.length };
  }
  const workerd = wranglerRequire('workerd').default;
  evidence.identities = {
    git_head: command('git', ['rev-parse', 'HEAD']), tools, artifacts,
    source_tree_sha256: sha(JSON.stringify(hashes)), source_files_sha256: hashes,
    tracked_diff_sha256: sha(command('git', ['diff', '--binary', 'HEAD', '--', 'experiments/workers-g4'])),
    node_executable_sha256: sha(await readFile(await realpath(process.execPath))),
    workerd_executable_sha256: sha(await readFile(workerd)),
    build_environment: Object.fromEntries(['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
      'CARGO_PROFILE_RELEASE_OPT_LEVEL', 'CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_CODEGEN_UNITS',
      'CARGO_PROFILE_RELEASE_PANIC', 'CARGO_PROFILE_RELEASE_DEBUG', 'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS',
      'CARGO_PROFILE_RELEASE_STRIP', 'CARGO_INCREMENTAL'].map(name => [name, process.env[name] ?? null])),
    build: 'Rust 1.94.0 release wasm32-unknown-unknown, locked G4 Cargo.lock; @lenso/workers-runtime build.mjs; wasm-bindgen 0.2.127 web/reset-state',
  };
  temp = await mkdtemp(resolve(tmpdir(), 'g4-d01-'));
  stage = 'bundle';
  const wasmName = 'lenso_workers_g4_host_bg.wasm';
  await copyFile(resolve(artifactDir, wasmName), resolve(temp, wasmName));
  await build({ entryPoints: [resolve(root, 'profile-worker.mjs')], outfile: resolve(temp, 'worker.mjs'),
    bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
    plugins: [{ name: 'd01-artifact', setup(b) {
      b.onResolve({ filter: /\.wasm$/ }, () => ({ path: `./${wasmName}`, external: true }));
      b.onResolve({ filter: /\/pkg\/lenso_workers_g4_host\.js$/ }, () => ({ path: resolve(artifactDir, 'lenso_workers_g4_host.js') }));
      b.onResolve({ filter: /^@lenso\/workers-runtime(?:\/.*)?$/ }, args => ({ path: require.resolve(args.path) }));
      b.onResolve({ filter: /^\.\.\/(clock|cancellation)\.mjs$/ }, args => ({ path: resolve(root, args.path.slice(3)) }));
    } }],
  });
  evidence.identities.bundle_sha256 = sha(await readFile(resolve(temp, 'worker.mjs')));
  stage = 'local_listener';
  await new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => server.close(resolve));
  });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'proof-rsa', alg: 'RS256', use: 'sig' };
  const secrets = { signing: randomBytes(32).toString('base64url'), pepper: randomBytes(32).toString('base64url'),
    oauth: randomBytes(16).toString('hex'), otp: randomBytes(32).toString('base64url'),
    providerSigning: privateKey.export({ type: 'pkcs8', format: 'pem' }), providerJwks: JSON.stringify({ keys: [jwk] }) };
  const start = ownerCount => {
    assert.equal(active, undefined);
    processNumber++;
    active = new Miniflare({ modules: true, scriptPath: resolve(temp, 'worker.mjs'), modulesRoot: temp,
      rootPath: temp, host: '127.0.0.1', port: 0,
      modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
      compatibilityDate: '2026-07-01',
      d1Databases: Object.fromEntries(bindings.slice(0, ownerCount).map(b => [b, `d01-${ownerCount}-${b}`])),
      d1Persist: resolve(temp, `d1-${ownerCount}`), bindings: { SECRETS: secrets },
      outboundService: () => new Response('D01 outbound disabled', { status: 503 }),
    });
  };
  const dispose = async () => { if (active) { await active.dispose(); active = undefined; } };
  const request = async (input, started = process.hrtime.bigint()) => {
    interrupted.signal.throwIfAborted();
    const url = await active.ready;
    const response = await fetch(url, { method: 'POST', body: JSON.stringify(input), signal: AbortSignal.any([interrupted.signal, AbortSignal.timeout(30000)]) });
    const body = await response.text();
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    return { status: response.status, body: JSON.parse(body), elapsed };
  };
  const successful = r => r.status === 200 && r.body.result.ready === true && r.body.result.shutdown === 'clean';
  const ok = r => successful(r) && Object.hasOwn(r.body.result.outcome, 'Ok');
  const verify = r => successful(r) && r.body.result.outcome.valid === true && r.body.result.outcome.wrong_audience_rejected === true;
  const ready = (r, n) => ok(r) && r.body.result.outcome.Ok.owners === n &&
    Object.entries(r.body.observations.d1).filter(([, c]) => c.calls > 0).length === n;
  const control = async input => {
    const r = await request(input);
    assert.ok(input.operation === 'setup' ? r.status === 200 && r.body.result.setup : ok(r), `Control failed: ${input.operation}`);
    return r.body.result.outcome?.Ok;
  };
  const measure = async (name, input, validate, started) => {
    stage = name;
    const r = await request(input, started);
    const row = evidence.scenarios[name];
    const domain = Boolean(r.body.result.outcome?.Err), runtime = r.status !== 200;
    const passed = validate(r);
    row.samples.push({ wall_ms: r.elapsed, http_status: r.status, passed, process: processNumber, ...r.body.observations });
    row.failure_counts.unexpected += Number(!passed);
    row.failure_counts.domain += Number(domain);
    row.failure_counts.runtime += Number(runtime);
    assert.ok(passed, `Scenario failed: ${name}`);
    return r.body.result.outcome?.Ok;
  };
  for (const n of [1, 7]) {
    stage = `setup_${n}`;
    start(n); await control({ operation: 'setup' }); await dispose();
    for (let i = 0; i < coldSamples; i++) {
      const started = process.hrtime.bigint();
      start(n);
      await measure(`cold_ready_${n}`, { owners: n, operation: 'ready', request: {} }, r => ready(r, n), started);
      await dispose();
    }
    start(n); await control({ owners: n, operation: 'ready', request: {} });
    for (let i = 0; i < samples; i++) await measure(`warm_ready_${n}`, { owners: n, operation: 'ready', request: {} }, r => ready(r, n));
    if (n === 1) await dispose();
  }
  const input = (operation, request = {}, fault) => ({ owners: 7, operation, request, fault });
  const identifier = `d01-${randomBytes(16).toString('hex')}`, password = randomBytes(24).toString('base64url');
  const registered = await control(input('password.register', { identifier, password }));
  for (let i = 0; i < samples; i++) await measure('password_valid', input('password.login', { identifier, password }), r => ok(r) && r.body.result.outcome.Ok.subject === registered.subject);
  for (let i = 0; i < samples; i++) {
    await control(input('password.login', { identifier, password }));
    await measure('password_invalid', input('password.login', { identifier, password: randomBytes(24).toString('base64url') }), r => successful(r) && r.body.result.outcome.Err === 'invalid_credentials');
  }
  for (let i = 0; i < samples; i++) await measure('password_absent', input('password.login', { identifier: `absent-${randomBytes(16).toString('hex')}`, password }), r => successful(r) && r.body.result.outcome.Err === 'invalid_credentials');
  const spec = { subject: registered.subject, actor_kind: 'service', assurance: 'api_token', audience: ['proof.resource@1:read'], claims: {}, expires_at: new Date(Date.now() + 3600000).toISOString() };
  let token = await control(input('api.issue', spec));
  for (let i = 0; i < samples; i++) token = await measure('api_issue', input('api.issue', spec), ok);
  const credential = { scheme: 'bearer', value: token.credential };
  for (let i = 0; i < samples; i++) await measure('api_verify', input('api.verify_target', { credential }), verify);
  for (let i = 0; i < samples; i++) {
    await measure('oidc_activation_probe', input('oidc.metadata'), r => ok(r) && r.body.result.outcome.Ok.issuer === 'https://oidc.proof.invalid');
    const keys = await control(input('oidc.jwks'));
    assert.ok(keys.jwks.keys[0].n === jwk.n && keys.jwks.keys[0].kid === jwk.kid, 'OIDC public key probe');
  }
  for (const [fault, failure, recovery] of [['storage', 'storage_failure', 'storage_recovery'], ['abandon', 'abandonment', 'abandonment_recovery']]) {
    for (let i = 0; i < samples; i++) {
      await measure(failure, input('ready', {}, fault), r => r.status === 503 && r.body.result.runtime_failure === true &&
        r.body.observations.generation_after > r.body.observations.generation_before);
      await measure(recovery, input('api.verify_target', { credential }), verify);
    }
  }
  await dispose();
  evidence.status = 'passed';
} catch (error) {
  evidence.status = stage === 'local_listener' && ['EPERM', 'EACCES'].includes(error.code) ? 'blocked' : 'failed';
  evidence.unresolved = { stage, code: error.code || 'validation_or_runtime_failure',
    reason: evidence.status === 'blocked' ? 'Environment prohibits a task-owned loopback listener; no runtime samples executed.' : 'Stage did not complete. Details intentionally excluded to avoid credential disclosure.' };
  process.exitCode = 1;
} finally {
  try { if (active) await active.dispose(); evidence.cleanup.processes_disposed = true; }
  catch { evidence.cleanup.processes_disposed = false; evidence.status = 'failed'; process.exitCode = 1; }
  if (temp && evidence.cleanup.processes_disposed) await rm(temp, { recursive: true, force: true });
  evidence.cleanup.resources_removed = !temp || evidence.cleanup.processes_disposed;
  for (const row of Object.values(evidence.scenarios)) {
    row.sample_count = row.samples.length;
    row.wall_ms = row.sample_count ? distribution(row.samples.map(s => s.wall_ms)) : null;
    row.d1_distributions = {};
    for (const owner of owners) {
      const observed = row.samples.map(s => s.d1[owner]).filter(Boolean);
      if (observed.length) row.d1_distributions[owner] = Object.fromEntries(
        Object.keys(observed[0]).map(key => [key, observed.every(c => c[key] !== null) ? distribution(observed.map(c => c[key])) : null]));
    }
    row.generation_changes = row.samples.filter(s => s.generation_after !== s.generation_before).length;
    row.wasm_observed_max_bytes = row.sample_count ? Math.max(...row.samples.flatMap(s => s.memory.map(m => m.bytes))) : null;
  }
  evidence.finished_at = new Date().toISOString();
  await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(`D01 ${evidence.status}: ${relative(repo, output)}`);
  process.off('SIGINT', stop); process.off('SIGTERM', stop);
}
