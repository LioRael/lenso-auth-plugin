// Executes actual owner Rust migrations through workerd's primary D1 binding.
import assert from 'node:assert/strict';
import { readdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
const { Miniflare } = wranglerRequire('miniflare');
const { build } = wranglerRequire('esbuild');
const root = fileURLToPath(new URL('.', import.meta.url));
const output = `${root}migration-proof.bundle.mjs`;
const owners = ['account', 'oauth-flow', 'password', 'phone', 'device', 'api-token', 'oidc'];
await build({
  entryPoints: [`${root}migration-proof-worker.mjs`], outfile: output, bundle: true,
  format: 'esm', platform: 'browser', target: 'es2022',
  plugins: [{ name: 'worker-wasm', setup(b) { b.onResolve({ filter: /\.wasm$/ }, args => ({ path: args.path, external: true })); } }],
});
const bindings = Object.fromEntries(owners.flatMap((owner, i) => ['fresh', 'legacy'].map(mode => [`DB_${i}_${mode}`, `${owner}-${mode}`])));
bindings.DB_UPGRADE = "pending-upgrade";
const mf = new Miniflare({
  modules: true, scriptPath: output, modulesRoot: root,
  modulesRules: [{ type: 'CompiledWasm', include: ['**/*.wasm'] }],
  compatibilityDate: '2026-07-08', d1Databases: bindings,
});
const receipts = [];
try {
  for (const [i, owner] of owners.entries()) {
    for (const mode of ['fresh', 'legacy']) {
      const binding = `DB_${i}_${mode}`;
      const db = await mf.getD1Database(binding);
      const call = async action => {
        const response = await mf.dispatchFetch(`http://local/?owner=${owner}&binding=${binding}&action=${action}`);
        const body = await response.text();
        const result = response.ok
          ? JSON.parse(body)
          : { ok: false, status: response.status, body };
        return result;
      };
      assert.equal((await call('verify')).ok, false, `${owner}: missing history must fail`);
      if (mode === 'legacy') {
        const directory = new URL(`../../crates/lenso-auth-${owner}-plugin/migrations/d1/`, import.meta.url);
        const migrations = (await readdir(directory)).sort();
        const initial = migrations[0];
        const statements = JSON.parse(execFileSync('python3', [fileURLToPath(new URL('../../workers/generate-migrations.py', import.meta.url)), '--statements', fileURLToPath(new URL(initial, directory))], { encoding: 'utf8' }));
        await db.batch(statements.map(sql => db.prepare(sql)));
        assert.equal((await call('setup')).ok, false, `${owner}: legacy needs explicit adoption`);
        assert.equal((await call('adopt-legacy')).ok, true, `${owner}: adopt`);
        if (migrations.length > 1) {
          // Adoption records only the known legacy v1 schema. A later authored
          // migration must remain an explicit operator upgrade rather than an
          // implicit Ready-time write.
          assert.equal((await call('verify')).ok, false, `${owner}: legacy upgrade remains pending`);
          assert.equal((await call('upgrade')).ok, true, `${owner}: upgrade adopted legacy`);
        }
      } else {
        assert.equal((await call('setup')).ok, true, `${owner}: setup`);
      }
      const verified = await call('verify');
      assert.equal(verified.ok, true, `${owner}: verify ${JSON.stringify(verified)}`);
      const before = await db.prepare('SELECT * FROM _lenso_migrations').all();
      assert.equal((await call('upgrade')).ok, true, `${owner}: current upgrade`);
      assert.deepEqual((await db.prepare('SELECT * FROM _lenso_migrations').all()).results, before.results);
      await db.prepare("UPDATE _lenso_migrations SET checksum='drift'").run();
      assert.equal((await call('verify')).ok, false, `${owner}: checksum drift`);
      // Owners with more than one migration retain a checksum row per version.
      // Restore the complete pre-fault ledger, not just the first row, so this
      // exercises checksum recovery rather than leaving a later migration
      // deliberately corrupted.
      for (const migration of before.results) {
        await db
          .prepare(
            "UPDATE _lenso_migrations SET checksum=?1 WHERE owner=?2 AND backend=?3 AND version=?4",
          )
          .bind(
            migration.checksum,
            migration.owner,
            migration.backend,
            migration.version,
          )
          .run();
      }
      assert.equal((await call('verify')).ok, true, `${owner}: restore exact history`);
      receipts.push({ owner, mode, passed: true });
    }
  }
  const upgradeDb = await mf.getD1Database('DB_UPGRADE');
  const upgrade = async (owner, action) => {
    const response = await mf.dispatchFetch(`http://local/?owner=${owner}&binding=DB_UPGRADE&action=${action}`);
    return response.ok;
  };
  assert.equal(await upgrade('fixture-v1', 'setup'), true);
  await upgradeDb.prepare('INSERT INTO migration_fixture(id) VALUES(7)').run();
  assert.equal(await upgrade('fixture-v2', 'verify'), false);
  assert.equal(await upgrade('fixture-v2', 'upgrade'), true);
  assert.equal(await upgrade('fixture-v2', 'verify'), true);
  assert.deepEqual((await upgradeDb.prepare('SELECT id,label FROM migration_fixture').all()).results, [{ id: 7, label: null }]);
  assert.equal(await upgrade('fixture-failed-v3', 'upgrade'), false);
  assert.equal(await upgrade('fixture-v2', 'verify'), true);
  assert.equal((await upgradeDb.prepare("SELECT name FROM sqlite_master WHERE name='rollback_marker'").all()).results.length, 0);
  receipts.push({ owner: 'test-only-upgrade', mode: 'pending-and-rollback', passed: true });
  console.log(JSON.stringify({ runtime: 'local workerd with actual D1 bindings', wasm_sha256: createHash('sha256').update(await readFile(new URL('./pkg/lenso_workers_g4_host_bg.wasm', import.meta.url))).digest('hex'), compositions: receipts.length, receipts }, null, 2));
} finally {
  await mf.dispose();
  await rm(output, { force: true });
}
