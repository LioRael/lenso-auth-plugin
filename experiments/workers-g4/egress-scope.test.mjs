import test from 'node:test';
import assert from 'node:assert/strict';
import {createEgressScope} from './egress-scope.mjs';
import {createEventHttpFetch} from '../../../../lenso-web/feat-workers-http-parity/crates/lenso-http-egress-plugin/js/event-fetch.mjs';
import {createEventRunner} from '../../../../lenso-runtime-rust/design-workers-compatibility/experiments/workers-runtime/runner.mjs';
const request={url:'https://idp.invalid/token',method:'POST',headers:[],body:new Uint8Array(),limits:{max_response_body_bytes:1024,max_response_head_bytes:1024,request_timeout_millis:1000}};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function setup(fetch) {return createEgressScope({createTransport:createEventHttpFetch,fetch,setTimeout,clearTimeout,cleanupTimeoutMs:5})}
test('peer abandonment fences pending Fetch before reset, aborts it, and rejects uncertain cleanup',async()=>{
 let release, signal, callbacks=0, cancelled=0, reset=0;
 const scope=setup((_url,options)=>{signal=options.signal;return new Promise(resolve=>release=resolve)});
 const runner=createEventRunner({instantiate:()=>({memory:{buffer:new ArrayBuffer(8)},__wasm_call_ctors(){}}),resetState:()=>{reset++},clearTimers(){},eventLimitMs:1000});
 const active=runner.run(()=>scope.fetch(request).promise.then(()=>{callbacks++;return '{}'},()=>{callbacks++;return '{}'}),{scope});
 const activeRejected=assert.rejects(active,/storage_cleanup_unconfirmed/);
 await assert.rejects(runner.run(()=>{throw new Error('peer trap')}),/abandoned/);
 await activeRejected;
 assert.equal(reset,1);assert.equal(signal.aborted,true);assert.equal(callbacks,0);
 release(new Response(new ReadableStream({cancel(){cancelled++}})));
 await tick();await tick();
 assert.equal(cancelled,1);assert.equal(callbacks,0);assert.equal(await scope.settled(),true);
 assert.equal((await runner.run(()=>'{}')).generation,2);
 await assert.rejects(scope.fetch(request).promise,e=>e.code==='transport_failure');
});
test('late rejection is handled without reaching invalidated callbacks',async()=>{
 let reject, callbacks=0;
 const scope=setup(()=>new Promise((_resolve,r)=>reject=r));
 scope.fetch(request).promise.then(()=>callbacks++,()=>callbacks++);
 scope.invalidate();scope.abort();assert.equal(await scope.settled(),false);
 reject(new Error('late native rejection'));await tick();
 assert.equal(callbacks,0);assert.equal(await scope.settled(),true);
});
test('pending body read and reader cancellation remain tracked after transport abort',async()=>{
 let releaseRead, cancelled=0, callbacks=0;const releaseCancel=[];
 const scope=setup(async()=>({status:200,headers:new Headers(),redirected:false,body:{getReader(){return {
  read:()=>new Promise(resolve=>releaseRead=resolve),
  cancel:()=>{cancelled++;return new Promise(resolve=>releaseCancel.push(resolve))},releaseLock(){},
 }}}}));
 scope.fetch(request).promise.then(()=>callbacks++,()=>callbacks++);
 await tick();scope.invalidate();scope.abort();const settling=scope.settled();
 await tick();assert.ok(cancelled>1);releaseRead({done:true});releaseCancel[0]();
 assert.equal(await settling,false);
 releaseCancel.forEach(resolve=>resolve());await tick();
 assert.equal(callbacks,0);assert.equal(await scope.settled(),true);
});
test('normal result passes through and all owner work settles',async()=>{
 const scope=setup(async()=>new Response('hello'));
 const result=await scope.fetch(request).promise;
 assert.equal(result.status,200);assert.equal(new TextDecoder().decode(result.body),'hello');
 scope.abort();assert.equal(await scope.settled(),true);scope.invalidate();
});
