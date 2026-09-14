import test from 'node:test';
import assert from 'node:assert/strict';
import {createD1StorageScope} from './d1-binding.mjs';
test('event closure blocks new I/O and waits for admitted native work',async()=>{
 let resolve,calls=0;const pending=new Promise(r=>resolve=r);
 const database={prepare(sql){return {bind(...params){return {sql,params}}}},batch(statements){calls++;assert.equal(statements[0].sql,'SELECT 1');return pending}};
 const scope=createD1StorageScope(),batch=scope.bind(database),operation=batch(JSON.stringify([{sql:'SELECT 1',params:[]}])) ;scope.close();
 await assert.rejects(batch('[]'),/closed/);assert.equal(calls,1);
 let settled=false;const cleanup=scope.settled().then(()=>{settled=true});await Promise.resolve();assert.equal(settled,false);
 resolve([{success:true,results:[{value:1}],meta:{changes:0}}]);assert.equal(JSON.parse(await operation)[0].success,true);await cleanup;assert.equal(settled,true);
});
test('binding absence fails before D1 admission',()=>{assert.throws(()=>createD1StorageScope().bind(undefined),/configured D1/)});
test('uncertain native work is bounded and late completion never calls abandoned Wasm',async()=>{
 let resolve;const pending=new Promise(r=>resolve=r);
 const scope=createD1StorageScope({cleanupTimeoutMs:5});
 const batch=scope.bind({prepare(){return {bind(){return {}}}},batch(){return pending}});
 let forwarded=false;batch('[{"sql":"SELECT 1","params":[]}]').then(()=>forwarded=true,()=>forwarded=true);
 scope.invalidate();assert.equal(await scope.settled(),false);
 resolve([{success:true}]);await Promise.resolve();await Promise.resolve();
 assert.equal(forwarded,false);assert.equal(await scope.settled(),true);
});
