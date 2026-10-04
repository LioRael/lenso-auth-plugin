import test from 'node:test';
import assert from 'node:assert/strict';
import {create} from '../src/host_facilities/state.mjs';

function fixture() {
  const calls = [];
  const database = {
    prepare(sql) { calls.push(['prepare', sql]); return {bind(...params) { return {sql, params}; }}; },
    async batch(statements) { calls.push(['batch', statements]); return statements.map(() => ({success: true, results: []})); },
  };
  const scope = {async run(work, encode) { calls.push(['scope']); return encode(await work()); }};
  return {database, scope, calls};
}

test('logical and legacy attachments keep the original primary batch transport', async () => {
  for (const extra of [{}, {storage_ref: 'auth/account'}]) {
    const {database, scope, calls} = fixture();
    const binding = create(database, scope, {profile: 'workers-d1', binding: 'AUTH_D1', ...extra});
    assert.equal(binding.name, 'AUTH_D1');
    assert.equal(binding.storage_ref, extra.storage_ref);
    assert.equal(Object.isFrozen(binding), true);
    assert.deepEqual(calls, []);
    const input = [{sql: 'owner statement fixture', params: ['fixture']}];
    assert.deepEqual(JSON.parse(await binding.batch(JSON.stringify(input))), [{success: true, results: []}]);
    assert.deepEqual(calls, [['scope'], ['prepare', 'owner statement fixture'], ['batch', input]]);
  }
});

test('invalid storage references and unexpected fields reject before transport I/O', () => {
  const {database, scope, calls} = fixture();
  for (const storage_ref of ['', null, '../account', '/account', 'a//b', 'a/..', 'postgres://url', 42]) {
    assert.throws(() => create(database, scope, {profile: 'workers-d1', binding: 'AUTH_D1', storage_ref}));
  }
  assert.throws(() => create(database, scope, {profile: 'workers-d1', binding: 'AUTH_D1', storage_ref: 'auth/account', migration: true}));
  assert.throws(() => create(database, scope, {profile: 'workers-d1', binding: 'bad/name', storage_ref: 'auth/account'}));
  assert.throws(() => create(database, scope, {profile: 'native-pg', binding: 'AUTH_D1', storage_ref: 'auth/account'}));
  assert.deepEqual(calls, []);
});

test('distinct Instances retain distinct logical references', () => {
  const {database, scope} = fixture();
  const a = create(database, scope, {profile: 'workers-d1', binding: 'ACCOUNT_D1', storage_ref: 'auth/account'});
  const b = create(database, scope, {profile: 'workers-d1', binding: 'PASSWORD_D1', storage_ref: 'auth/password'});
  assert.notEqual(a.storage_ref, b.storage_ref);
  assert.notEqual(a.name, b.name);
});
