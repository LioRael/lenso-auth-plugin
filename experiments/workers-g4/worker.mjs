import {initSync,__wbg_reset_state,invoke,handle_http} from './pkg/lenso_workers_g4_host.js';
import module from './pkg/lenso_workers_g4_host_bg.wasm';
import {clearTimers} from './clock.mjs';
import {createEventRunner} from '@lenso/workers-runtime/runner';
import {createHttpHandler} from '@lenso/workers-runtime/http';
import {createEventScope} from '@lenso/workers-runtime';
import {createD1Binding} from '../../workers/d1-binding.mjs';
import {createScopedHttpFetch} from '@lenso/http-egress-workers';
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
 const egressProof={started:false,aborted:false};
 const proofFetch=(url,options)=>{
  if(request.headers.get('x-proof-fault')!=='egress-abandon'||new URL(url).pathname!=='/fixture/token')return fetch(url,options);
  egressProof.started=true;
  options.signal.addEventListener('abort',()=>{egressProof.aborted=true},{once:true});
  const native=fetch(url,{...options,headers:[...options.headers,['x-proof-delay',env.PROOF_KEY]]});
  setTimeout(()=>{void runner.run(()=>{throw new Error('qualification pending egress abandonment')}).catch(()=>{})},10);
  return native;
 };
 return createEventScope(scope=>({
  signing:env.SIGNING_KEY,pepper:env.TOKEN_PEPPER,oauth:env.OAUTH_KEY,oidc:env.OIDC_SECRET,
  origin:new URL(request.url).origin,egressProof,
  otp:env.OTP_SECRET,providerSigning:env.PROVIDER_SIGNING_KEY,providerJwks:JSON.stringify(env.PROVIDER_JWKS),
  ...Object.fromEntries([['passwordBatch','PASSWORD_DB'],['phoneBatch','PHONE_DB'],['deviceBatch','DEVICE_DB'],['apiBatch','API_TOKEN_DB'],['oidcBatch','OIDC_DB']].filter(([,binding])=>env[binding] && request.headers.get('x-proof-fault')!=='method-missing-binding').map(([name,binding])=>[name,createD1Binding(request.headers.get('x-proof-fault')==='method-storage'?{prepare:sql=>env[binding].prepare(sql),batch:()=>Promise.reject(new Error('qualification method storage unavailable'))}:env[binding],scope)])),
  accountBatch:createD1Binding(request.headers.get("x-proof-fault")==="storage"?{prepare:sql=>env.ACCOUNT_DB.prepare(sql),batch:()=>env.ACCOUNT_DB.batch([env.ACCOUNT_DB.prepare("SELECT 1 FROM g4_deliberately_missing_table")])}:env.ACCOUNT_DB,scope),
  oauthBatch:createD1Binding(proofDatabase(env.OAUTH_DB,request.headers.get("x-proof-fault")),scope),
  httpFetch:createScopedHttpFetch(scope,{fetch:proofFetch,setTimeout,clearTimeout}),
 }));
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
 catch(error){return Response.json({runtime_failure:true,detail:String(error),...(request.headers.get('x-proof-fault')==='egress-abandon'?{egress_proof:scope.egressProof}: {})},{status:503,headers:{'cache-control':'no-store'}});}
 }};
