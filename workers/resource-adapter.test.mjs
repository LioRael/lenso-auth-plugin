import test from 'node:test';
import assert from 'node:assert/strict';
import {copyFile, mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {generateResourceAdapters, resourceOwners} from './generate-resource-adapters.mjs';

generateResourceAdapters({check: true});

function fixture() {
  const calls = [];
  const database = {
    prepare(sql) { calls.push(['prepare', sql]); return {bind(...params) { return {sql, params}; }}; },
    async batch(statements) { calls.push(['batch', statements]); return statements.map(() => ({success: true, results: []})); },
  };
  const scope = {async run(work, encode) { calls.push(['scope']); return encode(await work()); }};
  return {database, scope, calls};
}

for (const owner of resourceOwners) {
  const directory = new URL(`../crates/lenso-auth-${owner}-plugin/src/host_facilities/`, import.meta.url);
  const legacy = await import(new URL('state.mjs', directory));
  const adapter = await import(new URL('state-resource.mjs', directory));
  const configuration = {implementation: 'relay.auth-d1', profile: 'workers-d1',
    binding: `${owner.toUpperCase()}_DB`, storage_ref: `auth/${owner}`};

  test(`${owner}: copied single-file resource supports both exports and primary event transport`, async () => {
    const stage = await mkdtemp(join(tmpdir(), 'auth-resource-stage-'));
    try {
      const path = join(stage, 'owner_0.mjs');
      await copyFile(new URL('state-resource.mjs', directory), path);
      assert.deepEqual(await readFile(path), await readFile(new URL('state-resource.mjs', directory)));
      const staged = await import(pathToFileURL(path));
      assert.equal(typeof staged.createD1Binding, 'function');
      const {database, scope, calls} = fixture();
      const binding = staged.create(database, scope, configuration);
      assert.equal(binding.name, configuration.binding);
      assert.equal(binding.storage_ref, configuration.storage_ref);
      assert.equal(Object.isFrozen(binding), true);
      assert.deepEqual(calls, []);
      const input = [{sql: 'owner statement fixture', params: ['fixture']}];
      assert.deepEqual(JSON.parse(await binding.batch(JSON.stringify(input))), [{success: true, results: []}]);
      assert.deepEqual(calls, [['scope'], ['prepare', 'owner statement fixture'], ['batch', input]]);
      calls.length = 0;
      await staged.createD1Binding(database, scope)(JSON.stringify(input));
      assert.deepEqual(calls, [['scope'], ['prepare', 'owner statement fixture'], ['batch', input]]);
      assert.equal(configuration.implementation, 'relay.auth-d1');
    } finally { await rm(stage, {recursive: true, force: true}); }
  });

  test(`${owner}: resource metadata and private fields fail closed before I/O`, () => {
    const {database, scope, calls} = fixture();
    for (const invalid of [null, [], {}, {...configuration, implementation: 'other'},
      {...configuration, implementation: null}, Object.assign(Object.create({implementation: 'relay.auth-d1'}),
        {profile: 'workers-d1', binding: configuration.binding, storage_ref: configuration.storage_ref})]) {
      assert.throws(() => adapter.create(database, scope, invalid), /incompatible_target_resource/);
    }
    for (const extra of [{profile: 'native-pg'}, {binding: 'bad/name'}, {migration: true},
      {storage_ref: '../account'}, {storage_ref: null}, {storage_ref: ''}]) {
      assert.throws(() => adapter.create(database, scope, {...configuration, ...extra}), /invalid_auth_d1_facility/);
    }
    assert.deepEqual(calls, []);
  });

  test(`${owner}: legacy factory retains its original payload contract and failures propagate`, async () => {
    const {database, scope, calls} = fixture();
    const {implementation, ...original} = configuration;
    assert.equal(legacy.create(database, scope, original).storage_ref, original.storage_ref);
    assert.throws(() => legacy.create(database, scope, configuration), /invalid_auth_d1_facility/);
    const {storage_ref, ...withoutReference} = original;
    assert.equal(legacy.create(database, scope, withoutReference).storage_ref, undefined);
    assert.equal(adapter.create(database, scope, {implementation, ...withoutReference}).storage_ref, undefined);
    database.batch = async () => { throw new Error('synthetic transport unavailable'); };
    await assert.rejects(adapter.create(database, scope, configuration).batch(
      JSON.stringify([{sql: 'owner statement fixture', params: []}])), /synthetic transport unavailable/);
    assert.deepEqual(calls, [['scope'], ['prepare', 'owner statement fixture']]);
  });
}
