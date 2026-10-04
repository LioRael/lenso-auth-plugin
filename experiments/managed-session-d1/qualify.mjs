// Actual owner Rust D1 Store + owner bridge against isolated local workerd D1.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root=fileURLToPath(new URL(".",import.meta.url));
const repository=resolve(root,"../..");
const receiptPath=process.argv[2];
if(process.argv.length>3)throw new Error("Usage: node qualify.mjs [receipt-path]");
if(receiptPath && resolve(receiptPath).startsWith(repository))throw new Error("Receipt must be outside source worktree");
const require=createRequire(process.env.LENSO_WRANGLER_PACKAGE ?? import.meta.url);
const wranglerPackage=require.resolve("wrangler/package.json");
const wranglerRequire=createRequire(wranglerPackage);
const {Miniflare,convertV4MiniflareOptions}=wranglerRequire("miniflare");
const {build}=wranglerRequire("esbuild");
const runtimePackage=process.env.LENSO_WORKERS_RUNTIME_PACKAGE ?? require.resolve("@lenso/workers-runtime");
const output=resolve(root,".proof.bundle.mjs");
const persistence=await mkdtemp(join(tmpdir(),"lenso-managed-session-d1-"));
const cases=[];
const policy={idle_timeout_seconds:60,absolute_timeout_seconds:600,renew_interval_seconds:5};
let mf,db,counter=0;
const digest=()=>[...Buffer.from(`synthetic-digest-${++counter}`)];
const scalar=async(sql,...params)=>(await db.prepare(sql).bind(...params).first());
const mutate=async(sql,...params)=>db.prepare(sql).bind(...params).run();
const rows=async(table)=>(await db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all()).results;
const snapshot=async()=>JSON.stringify(await Promise.all([rows("auth_sessions"),rows("auth_managed_sessions"),rows("auth_session_rotations")]));
const raw=(input,drop=false)=>mf.dispatchFetch("http://local/call",{method:"POST",headers:{"content-type":"application/json",...(drop?{"x-local-drop-response":"after-rotation"}:{})},body:JSON.stringify(input)});
const call=async(input)=>{
  const response=await raw(input);
  assert.equal(response.status,200,`local ${input.operation} storage transport failed`);
  assert.equal(response.headers.get("cache-control"),"no-store");
  return response.json();
};
const ensure=async(subject)=>{assert.equal((await call({operation:"ensure",subject}))[0],subject);};
const session=async({subject=`subject-${counter+1}`,managed=true,selectedPolicy=policy}={})=>{
  await ensure(subject);
  const token=digest(),id=`session-${counter}`;
  assert.equal(await call({operation:managed?"managed_issue":"issue",subject,session_id:id,digest:token,policy:selectedPolicy}),"Inserted");
  return {id,token,subject,selectedPolicy};
};
const due=async(s)=>mutate("UPDATE auth_managed_sessions SET last_renew_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-20 seconds') WHERE session_id=?1",s.id);
const renew=(s,newToken=digest(),selectedPolicy=s.selectedPolicy)=>call({operation:"renew",old_digest:s.token,new_digest:newToken,policy:selectedPolicy}).then(result=>({result,newToken}));
const load=(token)=>call({operation:"load",digest:token});
const metadata=(s,selectedPolicy=s.selectedPolicy)=>call({operation:"metadata",digest:s.token,policy:selectedPolicy});
const policyExpiry=(s,selectedPolicy=s.selectedPolicy)=>call({operation:"policy_expiry",session_id:s.id,policy:selectedPolicy});
const checkMetadata=async(s,expected,selectedPolicy=s.selectedPolicy)=>{
  const before=await snapshot();const result=await metadata(s,selectedPolicy);
  assert.equal(result.Err,expected);assert.equal(await snapshot(),before,"metadata rejection changed durable state");
};
const checkFailure=async(s,expected,selectedPolicy=s.selectedPolicy)=>{
  const before=await snapshot();
  assert.equal((await renew(s,digest(),selectedPolicy)).result,expected);
  assert.equal(await snapshot(),before,`${expected} changed durable state`);
};

try {
  execFileSync(process.env.LENSO_CARGO ?? "cargo",["build","--locked","--offline","--target","wasm32-unknown-unknown","--release"],{cwd:root,stdio:"inherit"});
  execFileSync(process.env.LENSO_WASM_BINDGEN ?? "wasm-bindgen",["--target","web","--out-dir","pkg","--out-name","managed_session_d1","target/wasm32-unknown-unknown/release/lenso_managed_session_d1_proof.wasm"],{cwd:root,stdio:"inherit"});
  await build({entryPoints:[resolve(root,"proof-worker.mjs")],outfile:output,bundle:true,format:"esm",platform:"browser",target:"es2022",plugins:[
    {name:"wasm",setup(b){b.onResolve({filter:/\.wasm$/},a=>({path:a.path,external:true}));}},
    {name:"runtime",setup(b){b.onResolve({filter:/^@lenso\/workers-runtime$/},()=>({path:runtimePackage}));}},
  ]});
  const start=()=>new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:persistence,workers:[{name:"managed-session-proof",modules:[{type:"ESModule",path:output},{type:"CompiledWasm",path:resolve(root,"pkg/managed_session_d1_bg.wasm")}],modulesRoot:root,compatibilityDate:"2026-07-08",d1Databases:{ACCOUNT_DB:"local-managed-account"}}]}));
  mf=start();db=await mf.getD1Database("ACCOUNT_DB");
  const migrationDirectory=resolve(repository,"crates/lenso-auth-account-plugin/migrations/d1");
  const migrations=(await readdir(migrationDirectory)).filter(f=>f.endsWith(".sql")).sort();
  assert.equal(migrations.length,3,"Managed-session migration must be present");
  for(const file of migrations){
    const sql=await readFile(join(migrationDirectory,file),"utf8");
    // Owner SQL is executed explicitly against an ephemeral fixture only.
    for(const part of sql.replace(/--[^\n]*/g,"").split(";").map(p=>p.trim()).filter(Boolean))await db.prepare(part).run();
  }
  cases.push("Explicit owner migrations create isolated local D1 schema");

  const missingBefore=await snapshot();
  assert.equal(await call({operation:"managed_issue",subject:"absent-subject",session_id:"absent-session",digest:digest(),policy}),"InvalidSubject");
  assert.equal(await snapshot(),missingBefore);
  const disabled=await session();
  assert.equal(await call({operation:"disable",subject:disabled.subject}),true);
  const disabledBefore=await snapshot();
  assert.equal(await call({operation:"managed_issue",subject:disabled.subject,session_id:"disabled-new-session",digest:digest(),policy}),"Disabled");
  assert.equal(await snapshot(),disabledBefore);
  cases.push("Invalid and disabled subjects cannot create managed metadata or session");

  const s=await session();
  const initialMetadataBefore=await snapshot();
  const initialMetadata=(await metadata(s)).Ok;assert.ok(initialMetadata);
  assert.equal(initialMetadata.session_id,s.id);
  assert.deepEqual(Object.keys(initialMetadata).sort(),["absolute_expires_at","expires_at","renew_after","session_id"]);
  assert.equal(await snapshot(),initialMetadataBefore);
  cases.push("Initial current managed metadata is readable before renew due, credential-free and write-free");
  await checkFailure(s,"TooEarly");
  cases.push("TooEarly performs no writes");
  const absent={...s,token:digest()};await checkFailure(absent,"InvalidCredential");
  await checkMetadata(absent,"InvalidCredential");
  cases.push("Unknown digest cannot renew or change durable state");
  await due(s);
  const a=digest(),b=digest();
  const race=await Promise.all([renew(s,a),renew(s,b)]);
  assert.equal(race.filter(v=>v.result.Rotated).length,1);
  assert.equal(race.filter(v=>v.result==="StaleCredential").length,1);
  const winner=race.find(v=>v.result.Rotated);
  assert.equal(winner.result.Rotated.session_id,s.id);
  assert.equal(await load(s.token),null);
  assert.ok(await load(winner.newToken));
  assert.equal((await scalar("SELECT count(*) AS n FROM auth_session_rotations WHERE session_id=?1",s.id)).n,1);
  await checkFailure(s,"StaleCredential");
  await checkMetadata(s,"StaleCredential");
  cases.push("Concurrent same-token renewals have exactly one winner; stale replay leaves winner active");
  assert.equal(await call({operation:"revoke_credential",digest:s.token}),true);
  assert.equal((await load(winner.newToken)).revoked,true);
  await checkFailure({...s,token:winner.newToken},"Revoked");
  await checkMetadata({...s,token:winner.newToken},"Revoked");
  assert.equal(await call({operation:"revoke_credential",digest:s.token}),false);
  cases.push("Historical token logout revokes stable session and every future rotation");

  for(const order of ["revoke-first","renew-first","concurrent"]){
    const r=await session();await due(r);const next=digest();
    let outcome;
    if(order==="revoke-first"){
      assert.equal(await call({operation:"revoke_credential",digest:r.token}),true);
      outcome=(await renew(r,next)).result;assert.equal(outcome,"Revoked");
    }else if(order==="renew-first"){
      outcome=(await renew(r,next)).result;assert.ok(outcome.Rotated);
      assert.equal(await call({operation:"revoke_credential",digest:r.token}),true);
    }else{
      const pair=await Promise.all([renew(r,next),call({operation:"revoke_credential",digest:r.token})]);
      outcome=pair[0].result;assert.ok(outcome==="Revoked" || outcome.Rotated);assert.equal(pair[1],true);
    }
    assert.equal((await call({operation:"inspect",session_id:r.id})).revoked,true);
    if(outcome.Rotated)await checkFailure({...r,token:next},"Revoked");
  }
  cases.push("Revoke/renew both serial orders and a concurrent race cannot revive a session");
  for(const order of ["disable-first","renew-first","concurrent"]){
    const r=await session();await due(r);const next=digest();let outcome;
    if(order==="disable-first"){
      assert.equal(await call({operation:"disable",subject:r.subject}),true);
      outcome=(await renew(r,next)).result;assert.equal(outcome,"Revoked");
    }else if(order==="renew-first"){
      outcome=(await renew(r,next)).result;assert.ok(outcome.Rotated);
      assert.equal(await call({operation:"disable",subject:r.subject}),true);
    }else{
      const pair=await Promise.all([renew(r,next),call({operation:"disable",subject:r.subject})]);
      outcome=pair[0].result;assert.ok(outcome==="Revoked" || outcome.Rotated);assert.equal(pair[1],true);
    }
    assert.equal((await call({operation:"inspect",session_id:r.id})).revoked,true);
    if(outcome.Rotated)await checkFailure({...r,token:next},"Revoked");
  }
  cases.push("Subject disable/renew both serial orders and concurrent race cannot restore authority");

  const idle=await session();await due(idle);
  await mutate("UPDATE auth_sessions SET expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE session_id=?1",idle.id);
  await checkFailure(idle,"Expired");
  await checkMetadata(idle,"Expired");
  const absolute=await session();await due(absolute);
  await mutate("UPDATE auth_managed_sessions SET absolute_expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now') WHERE session_id=?1",absolute.id);
  await checkFailure(absolute,"Expired");
  await checkMetadata(absolute,"Expired");
  cases.push("Idle and absolute exact expiry boundaries reject without writes using D1 time");
  const narrow=await session();await due(narrow);
  await mutate("UPDATE auth_managed_sessions SET issued_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-120 seconds') WHERE session_id=?1",narrow.id);
  await checkFailure(narrow,"Expired",{...policy,absolute_timeout_seconds:60});
  cases.push("Narrowed current absolute policy rejects previously eligible session");
  const bounded=await session();await due(bounded);
  await mutate("UPDATE auth_managed_sessions SET absolute_expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','+12 seconds') WHERE session_id=?1",bounded.id);
  const boundedResult=(await renew(bounded)).result.Rotated;assert.ok(boundedResult);
  const boundedRow=await scalar("SELECT s.expires_at,m.absolute_expires_at FROM auth_sessions s JOIN auth_managed_sessions m USING(session_id) WHERE s.session_id=?1",bounded.id);
  assert.equal(boundedRow.expires_at,boundedRow.absolute_expires_at);
  cases.push("Rotation expiry cannot exceed frozen absolute deadline");
  const nearAbsolute=await session();await due(nearAbsolute);
  await mutate("UPDATE auth_managed_sessions SET absolute_expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','+2 seconds') WHERE session_id=?1",nearAbsolute.id);
  const nearResult=(await renew(nearAbsolute)).result.Rotated;assert.ok(nearResult);
  assert.deepEqual(nearResult.renew_after,nearResult.absolute_expires_at);
  const nearRow=await scalar("SELECT s.expires_at,m.absolute_expires_at,m.last_renew_at FROM auth_sessions s JOIN auth_managed_sessions m USING(session_id) WHERE s.session_id=?1",nearAbsolute.id);
  assert.equal(nearRow.expires_at,nearRow.absolute_expires_at);
  cases.push("Final eligible rotation remains bounded when next interval falls beyond absolute deadline");
  const narrowedIdle=await session();
  await mutate("UPDATE auth_managed_sessions SET last_renew_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-6 seconds') WHERE session_id=?1",narrowedIdle.id);
  assert.ok((await renew(narrowedIdle,digest(),{...policy,idle_timeout_seconds:12})).result.Rotated);
  const narrowedRow=await scalar("SELECT s.expires_at,m.last_renew_at FROM auth_sessions s JOIN auth_managed_sessions m USING(session_id) WHERE s.session_id=?1",narrowedIdle.id);
  assert.ok(Date.parse(narrowedRow.expires_at)-Date.parse(narrowedRow.last_renew_at)<=12000);
  const idleBeyondNarrowed=await session();await due(idleBeyondNarrowed);
  await checkFailure(idleBeyondNarrowed,"Expired",{...policy,idle_timeout_seconds:12});
  await checkMetadata(idleBeyondNarrowed,"Expired",{...policy,idle_timeout_seconds:12});
  cases.push("Current narrowed idle deadline rejects already-idle credential for both renewal and metadata without writes");
  const enlarged=await session();await due(enlarged);
  assert.ok((await renew(enlarged,digest(),{...policy,idle_timeout_seconds:120,absolute_timeout_seconds:1200,renew_interval_seconds:1})).result.Rotated);
  const enlargedRow=await scalar("SELECT s.expires_at,m.last_renew_at,m.absolute_expires_at FROM auth_sessions s JOIN auth_managed_sessions m USING(session_id) WHERE s.session_id=?1",enlarged.id);
  assert.ok(Date.parse(enlargedRow.expires_at)-Date.parse(enlargedRow.last_renew_at)<=60000);
  const interval=await session();await due(interval);await checkFailure(interval,"TooEarly",{...policy,renew_interval_seconds:30});
  cases.push("Current idle/interval policy narrows; broader policy cannot widen issued idle or absolute envelope");
  const collision=await session(),occupied=await session();await due(collision);
  const collisionBefore=await snapshot();
  const collisionResponse=await raw({operation:"renew",old_digest:collision.token,new_digest:occupied.token,policy});
  assert.equal(collisionResponse.status,500);
  assert.deepEqual(await collisionResponse.json(),{runtime_failure:"storage"});
  assert.equal(await snapshot(),collisionBefore);
  const sameDigestResponse=await raw({operation:"renew",old_digest:collision.token,new_digest:collision.token,policy});
  assert.equal(sameDigestResponse.status,500);assert.equal(await snapshot(),collisionBefore);
  cases.push("Digest collision rolls back complete batch without exposing parameters");
  const multiple=await session();await due(multiple);
  const firstRotation=await renew(multiple);assert.ok(firstRotation.result.Rotated);
  await due(multiple);
  const historicalCollisionBefore=await snapshot();
  assert.equal((await raw({operation:"renew",old_digest:firstRotation.newToken,new_digest:multiple.token,policy})).status,500);
  assert.equal(await snapshot(),historicalCollisionBefore);
  const secondRotation=await renew({...multiple,token:firstRotation.newToken});assert.ok(secondRotation.result.Rotated);
  assert.equal((await scalar("SELECT count(*) AS n FROM auth_session_rotations WHERE session_id=?1",multiple.id)).n,2);
  assert.equal(await call({operation:"revoke_credential",digest:multiple.token}),true);
  assert.equal((await load(secondRotation.newToken)).revoked,true);
  cases.push("Original digest still revokes stable session after multiple rotations");
  cases.push("New verifier cannot equal current or historical digest; rejected reuse leaves database unchanged");

  const legacy=await session({managed:false});
  assert.ok(await load(legacy.token));await checkFailure(legacy,"Unsupported");
  await checkMetadata(legacy,"Unsupported");
  assert.equal(await policyExpiry(legacy),null);
  const childToken=digest(),childId=`child-${counter}`;
  assert.ok((await call({operation:"grant",parent_digest:legacy.token,session_id:childId,digest:childToken})).Ok);
  assert.ok(await load(childToken));await checkFailure({...legacy,id:childId,token:childToken},"Unsupported");
  await checkMetadata({...legacy,id:childId,token:childToken},"Unsupported");
  assert.equal(await policyExpiry({...legacy,id:childId}),null);
  assert.equal(await call({operation:"revoke_credential",digest:legacy.token}),true);
  assert.equal((await load(childToken)).revoked,true);
  cases.push("Legacy issuance/auth lookup/revocation and bounded child delegation remain compatible; legacy and child cannot renew");
  const parent=await session(),managedChild=digest(),managedChildId=`child-${counter}`;
  assert.ok((await call({operation:"grant",parent_digest:parent.token,session_id:managedChildId,digest:managedChild})).Ok);
  const childBefore=await scalar("SELECT expires_at FROM auth_sessions WHERE session_id=?1",managedChildId);
  assert.equal(Date.parse(await policyExpiry({...parent,id:managedChildId})),Date.parse(childBefore.expires_at));
  await due(parent);assert.ok((await renew(parent)).result.Rotated);
  assert.ok(await load(managedChild));
  assert.equal((await scalar("SELECT expires_at FROM auth_sessions WHERE session_id=?1",managedChildId)).expires_at,childBefore.expires_at);
  assert.equal(await call({operation:"revoke_credential",digest:parent.token}),true);
  assert.equal((await load(managedChild)).revoked,true);
  cases.push("Managed parent rotation preserves stable child reference without extending child expiry; historical logout revokes child");
  cases.push("Read-only metadata uses same stale, revoked, idle/absolute expiry, legacy and delegated rejection semantics");
  for(const narrowed of ["idle","absolute"]){
    const rootSession=await session(),childDigest=digest(),session_id=`child-${counter}`;
    assert.ok((await call({operation:"grant",parent_digest:rootSession.token,session_id,digest:childDigest})).Ok);
    const descendant={...rootSession,id:session_id,token:childDigest};
    let selectedPolicy;
    if(narrowed==="idle"){
      await due(rootSession);selectedPolicy={...policy,idle_timeout_seconds:12};
    }else{
      await mutate("UPDATE auth_managed_sessions SET issued_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-120 seconds') WHERE session_id=?1",rootSession.id);
      selectedPolicy={...policy,absolute_timeout_seconds:60};
    }
    const before=await snapshot();
    const childStored=await scalar("SELECT expires_at FROM auth_sessions WHERE session_id=?1",session_id);
    assert.ok(Date.parse(childStored.expires_at)>Date.now());
    const bound=await policyExpiry(descendant,selectedPolicy);
    assert.ok(bound && Date.parse(bound)<=Date.now(),`managed parent ${narrowed} bound must expire still-future child`);
    assert.equal(Date.parse(bound),Date.parse(await policyExpiry(rootSession,selectedPolicy)));
    await checkMetadata(descendant,"Unsupported",selectedPolicy);
    await checkFailure(descendant,"Unsupported",selectedPolicy);
    assert.equal(await snapshot(),before);
  }
  cases.push("Private policy bound propagates managed parent's narrowed idle/absolute to delegated child without writes; child metadata/renewal stays unsupported");
  cases.push("Private policy bound preserves legacy parent/child expiry and the child's own earlier deadline");

  const lost=await session();await due(lost);const lostNew=digest();
  assert.equal((await raw({operation:"renew",old_digest:lost.token,new_digest:lostNew,policy},true)).status,599);
  assert.equal(await load(lost.token),null);
  assert.ok(await load(lostNew));await checkFailure(lost,"StaleCredential");
  cases.push("Lost successful rotation response leaves old token stale; no plaintext recovery or automatic mutation retry");
  const persisted=await session();await due(persisted);const persistedNew=digest();
  assert.ok((await renew(persisted,persistedNew)).result.Rotated);
  await mf.dispose();mf=start();db=await mf.getD1Database("ACCOUNT_DB");
  assert.equal(await load(persisted.token),null);assert.ok(await load(persistedNew));await checkFailure(persisted,"StaleCredential");
  assert.equal(await call({operation:"revoke_credential",digest:persisted.token}),true);
  assert.equal((await load(persistedNew)).revoked,true);
  cases.push("Workerd restart persists current digest, rotation replay rejection and historical logout authority");

  const sourcePaths=["crates/lenso-auth-account-plugin/src/storage/d1.rs","crates/lenso-auth-account-plugin/src/storage/d1_managed.rs","crates/lenso-auth-account-plugin/src/workers.rs","workers/d1-binding.mjs",...migrations.map(f=>`crates/lenso-auth-account-plugin/migrations/d1/${f}`)];
  const hashes={};for(const path of sourcePaths)hashes[path]=createHash("sha256").update(await readFile(resolve(repository,path))).digest("hex");
  const receipt={schema:"lenso.auth.managed-session-local-d1@1",backend:"actual-local-workerd-d1",passed:true,cloudResourcesCreated:false,sourceHashes:hashes,toolVersions:{wrangler:wranglerRequire("./package.json").version,miniflare:wranglerRequire("miniflare/package.json").version,wasmBindgen:execFileSync(process.env.LENSO_WASM_BINDGEN??"wasm-bindgen",["--version"],{encoding:"utf8"}).trim()},scope:"Actual Account D1 Rust functions and owner JS bridge; fixture model/request shims, no Kernel/Capability/caller ACL or browser Cookie gate",cases};
  if(receiptPath)await writeFile(receiptPath,JSON.stringify(receipt,null,2)+"\n");
  console.log(JSON.stringify(receipt,null,2));
} finally {
  if(mf)await mf.dispose();
  await rm(output,{force:true});
  await rm(persistence,{recursive:true,force:true});
}
