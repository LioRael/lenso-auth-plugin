import {initSync,__wbg_reset_state,invoke,handle_http} from './pkg/lenso_workers_g4_host.js';
import module from './pkg/lenso_workers_g4_host_bg.wasm';
import {clearTimers} from './clock.mjs';
import {createEventRunner} from '../../../../lenso-runtime-rust/design-workers-compatibility/experiments/workers-runtime/runner.mjs';
import {createCancellationScope,createHttpHandler} from '../../../../lenso-runtime-rust/design-workers-compatibility/experiments/workers-runtime/http.mjs';
import {createD1StorageScope} from '../../workers/d1-binding.mjs';
import {createEventHttpFetch} from '../../../../lenso-web/feat-workers-http-parity/crates/lenso-http-egress-plugin/js/event-fetch.mjs';
import {fixture} from './idp-fixture.mjs';
const runner=createEventRunner({instantiate:()=>initSync({module}),resetState:__wbg_reset_state,clearTimers,eventLimitMs:15000});
function proofDatabase(database,fault){
 if(fault!=="delayed-consume")return database;
 return {prepare(sql){return {bind(...params){return {sql,params}}}},async batch(statements){
  if(statements.some(s=>s.sql.startsWith("SELECT provider,")))await new Promise(resolve=>setTimeout(resolve,3000));
  return database.batch(statements.map(s=>database.prepare(s.sql).bind(...s.params)));
 }};
}
function createScope(request,env){
 const storage=createD1StorageScope();
 const scope=createCancellationScope({signing:env.SIGNING_KEY,pepper:env.TOKEN_PEPPER,oauth:env.OAUTH_KEY,oidc:env.OIDC_SECRET,origin:new URL(request.url).origin,accountBatch:storage.bind(request.headers.get("x-proof-fault")==="storage"?{prepare:sql=>env.ACCOUNT_DB.prepare(sql),batch:()=>env.ACCOUNT_DB.batch([env.ACCOUNT_DB.prepare("SELECT 1 FROM g4_deliberately_missing_table")])}:env.ACCOUNT_DB),oauthBatch:storage.bind(proofDatabase(env.OAUTH_DB,request.headers.get("x-proof-fault"))),httpFetch:createEventHttpFetch({fetch,setTimeout,clearTimeout})});
 const abort=scope.abort.bind(scope),invalidate=scope.invalidate.bind(scope);
 scope.abort=()=>{storage.close();abort()};scope.invalidate=()=>{storage.invalidate();invalidate()};scope.settled=()=>storage.settled();return scope;
}
export default {async fetch(request,env){
 const idp=await fixture(request,env);if(idp)return idp;
 if(!env.PROOF_KEY || request.headers.get('x-proof-key')!==env.PROOF_KEY)return new Response('Not found',{status:404});
 if(new URL(request.url).pathname.startsWith('/auth/'))return createHttpHandler({run:runner.run,handleHttp:handle_http,maxRequestBodyBytes:65536,maxResponseBodyBytes:65536,maxRequestHeadBytes:16384,bodyReadTimeoutMs:10000,createScope:r=>createScope(r,env)})(request);
 if(request.method!=='POST')return new Response('Method not allowed',{status:405});
 const reader=request.body?.getReader(),chunks=[];let size=0;if(reader){for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();return new Response('Too large',{status:413})}chunks.push(value)}}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
 const scope=createScope(request,env);
 try{const result=await runner.run(()=>{if(request.headers.get("x-proof-fault")==="abandon")throw new Error("qualification generation abandonment");return request.headers.has("x-proof-http")?handle_http(new TextDecoder().decode(bytes),scope):invoke(new TextDecoder().decode(bytes),scope)},{scope,signal:request.signal});return Response.json(result,{headers:{'cache-control':'no-store'}});}
 catch(error){return Response.json({runtime_failure:true,detail:String(error)},{status:503,headers:{'cache-control':'no-store'}});}
 }};
