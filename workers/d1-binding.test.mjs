import test from 'node:test';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import {createD1Binding} from './d1-binding.mjs';
import {createEventScope} from '@lenso/workers-runtime';
test('event closure blocks new I/O and waits for admitted native work',async()=>{
 let resolve,calls=0;const pending=new Promise(r=>resolve=r);
 const database={prepare(sql){return {bind(...params){return {sql,params}}}},batch(statements){calls++;assert.equal(statements[0].sql,'SELECT 1');return pending}};
 const scope=createEventScope(),batch=createD1Binding(database,scope),operation=batch(JSON.stringify([{sql:'SELECT 1',params:[]}])) ;scope.abort();
 await assert.rejects(batch('[]'),/closed/);assert.equal(calls,1);
 let settled=false;const cleanup=scope.settled().then(()=>{settled=true});await Promise.resolve();assert.equal(settled,false);
 resolve([{success:true,results:[{value:1}],meta:{changes:0}}]);assert.equal(JSON.parse(await operation)[0].success,true);await cleanup;assert.equal(settled,true);
});
test('binding absence fails before D1 admission',()=>{assert.throws(()=>createD1Binding(undefined,createEventScope()),/configured D1/)});
test('uncertain native work is bounded and late completion never calls abandoned Wasm',async()=>{
 let resolve;const pending=new Promise(r=>resolve=r);
 const scope=createEventScope({}, {cleanupTimeoutMs:5});
 const batch=createD1Binding({prepare(){return {bind(){return {}}}},batch(){return pending}},scope);
 let forwarded=false;batch('[{"sql":"SELECT 1","params":[]}]').then(()=>forwarded=true,()=>forwarded=true);
 scope.invalidate();assert.equal(await scope.settled(),false);
 resolve([{success:true}]);await Promise.resolve();await Promise.resolve();
 assert.equal(forwarded,false);assert.equal(await scope.settled(),false);
});

test('package-owned Rust bridges match the private canonical source',()=>{
 const source=readFileSync(new URL('./d1.rs',import.meta.url),'utf8');
 for(const owner of ['account','oauth-flow','device','password','oidc','phone','api-token']){
  const copy=readFileSync(new URL(`../crates/lenso-auth-${owner}-plugin/src/workers.rs`,import.meta.url),'utf8');
  assert.equal(copy,source,`${owner} workers.rs must match workers/d1.rs`);
 }
});
