// Actual Account Rust binding store and generated migration operators, local D1.
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtemp,readFile,rm,writeFile} from "node:fs/promises";
import {createRequire} from "node:module";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {fileURLToPath} from "node:url";

const root=fileURLToPath(new URL(".",import.meta.url));
const repository=resolve(root,"../..");
const targetRoot=resolve(process.env.CARGO_TARGET_DIR??join(root,"target"));
const receiptPath=process.argv[2];
if(process.argv.length>3)throw Error("Usage: node qualify.mjs [receipt-path]");
if(receiptPath&&resolve(receiptPath).startsWith(repository))throw Error("Receipt must be outside source worktree");
const require=createRequire(process.env.LENSO_WRANGLER_PACKAGE??import.meta.url);
const wranglerPackage=require.resolve("wrangler/package.json");
const wranglerRequire=createRequire(wranglerPackage);
const {Miniflare,convertV4MiniflareOptions}=wranglerRequire("miniflare");
const {build}=wranglerRequire("esbuild");
const runtimePackage=process.env.LENSO_WORKERS_RUNTIME_PACKAGE??require.resolve("@lenso/workers-runtime");
const output=join(root,".proof.bundle.mjs");
const persistence=await mkdtemp(join(tmpdir(),"lenso-operator-binding-d1-"));
const cases=[];
const config={source_issuer:"synthetic.accounts",source_account_instance:"lenso.auth.account/accounts",scope_kind:"deployment",scope_id:"synthetic-scope",deployment:"synthetic-deployment",bootstrap_subject:"usr_source",bootstrap_not_before:"2026-10-04T00:00:00Z",bootstrap_expires_at:"2026-10-04T00:10:00Z",workflow_callers:["lenso.auth.operator-session/default"]};
let mf,db,extra;
const sourceFiles=[
  "crates/lenso-auth-account-plugin/src/storage/operator_binding.rs",
  "crates/lenso-auth-account-plugin/src/operator_binding.rs",
  "crates/lenso-auth-account-plugin/src/workers.rs",
  "crates/lenso-auth-account-plugin/src/migration.rs",
  "workers/d1-binding.mjs",
  ...["001_account.sql","002_pagination_indexes.sql","003_managed_sessions.sql","004_operator_bindings.sql"].map(name=>`crates/lenso-auth-account-plugin/migrations/d1/${name}`),
];
const fixtureFiles=["Cargo.toml","Cargo.lock","src/lib.rs","proof-worker.mjs","qualify.mjs"];
const hashes=async(files,base)=>Object.fromEntries(await Promise.all(files.map(async file=>[file,createHash("sha256").update(await readFile(resolve(base,file))).digest("hex")])));
const callOn=async(runtime,input)=>{
  const response=await runtime.dispatchFetch("http://local/call",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(input)});
  assert.equal(response.status,200,`actual local ${input.operation} transport failed`);
  assert.equal(response.headers.get("cache-control"),"no-store");
  return response.json();
};
const call=input=>callOn(mf,{config,...input});
const migrate=(action,options={})=>call({operation:"migration",action,...options});
const read=(column,value,selected=config)=>call({operation:"read",column,value,config:selected});
const prepare=(subject,binding_id,operator,selected=config)=>call({operation:"prepare",subject,binding_id,operator,config:selected});
const activate=(binding_id,revision,audit,policy="policy-1",selected=config)=>call({operation:"activate",binding_id,revision,audit,policy,config:selected});
const revoke=(binding_id,actor,occurred,selected=config)=>call({operation:"revoke",binding_id,actor,occurred,config:selected});
const complete=(binding_id,revision,audit,selected=config)=>call({operation:"complete",binding_id,revision,audit,config:selected});
const identity=subject=>db.prepare("INSERT INTO identity_subjects(subject_id) VALUES(?1)").bind(subject).run();
const bindingRows=async()=>(await db.prepare("SELECT * FROM auth_operator_bindings ORDER BY binding_id").all()).results;
const snapshot=async()=>JSON.stringify(await bindingRows());
const schemaSnapshot=async(database=db)=>{
  const schema=(await database.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'sqlite_*' ORDER BY name").all()).results;
  const content=[];
  for(const {name} of schema)content.push((await database.prepare(`SELECT * FROM "${name.replaceAll('"','""')}" ORDER BY 1`).all()).results);
  return JSON.stringify([schema,content]);
};
const unchanged=async(operation)=>{const before=await snapshot();const value=await operation();assert.equal(await snapshot(),before,"rejected or replayed operation changed binding state");return value;};
const start=database=>new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:persistence,workers:[{name:"operator-binding-proof",modules:[{type:"ESModule",path:output},{type:"CompiledWasm",path:join(root,"pkg/operator_binding_d1_bg.wasm")}],modulesRoot:root,compatibilityDate:"2026-07-08",d1Databases:{ACCOUNT_DB:database}}]}));

try {
  const sourceHashes=await hashes(sourceFiles,repository);
  const fixtureHashes=await hashes(fixtureFiles,root);
  execFileSync(process.env.LENSO_CARGO??"cargo",["build","--locked","--offline","--target","wasm32-unknown-unknown","--release"],{cwd:root,stdio:"inherit"});
  execFileSync(process.env.LENSO_WASM_BINDGEN??"wasm-bindgen",["--target","web","--out-dir","pkg","--out-name","operator_binding_d1",join(targetRoot,"wasm32-unknown-unknown/release/lenso_operator_binding_d1_proof.wasm")],{cwd:root,stdio:"inherit"});
  await build({entryPoints:[join(root,"proof-worker.mjs")],outfile:output,bundle:true,format:"esm",platform:"browser",target:"es2022",plugins:[
    {name:"wasm",setup(b){b.onResolve({filter:/\.wasm$/},a=>({path:a.path,external:true}));}},
    {name:"runtime",setup(b){b.onResolve({filter:/^@lenso\/workers-runtime$/},()=>({path:runtimePackage}));}},
  ]});
  mf=start("local-operator-account");db=await mf.getD1Database("ACCOUNT_DB");
  assert.deepEqual(await migrate("setup_legacy"),{Ok:false});
  const v2=await schemaSnapshot();
  assert.deepEqual(await migrate("verify"),{Ok:false});
  assert.deepEqual(await migrate("verify",{managed_required:true}),{Err:"upgrade_required"});
  for(const managed_required of [false,true])assert.deepEqual(await migrate("verify",{managed_required,operator_required:true}),{Err:"upgrade_required"});
  assert.equal(await schemaSnapshot(),v2);
  assert.equal(await db.prepare("SELECT name FROM sqlite_master WHERE name='auth_operator_bindings'").first(),null);
  cases.push("Actual generated v2 setup and read-only verify_features preserve legacy admission; managed or binding mode refuses missing exact history without writes");
  assert.deepEqual(await migrate("upgrade_managed"),{Ok:true});
  const v3=await schemaSnapshot();
  for(const managed_required of [false,true]){
    assert.deepEqual(await migrate("verify",{managed_required}),{Ok:true});
    assert.deepEqual(await migrate("verify",{managed_required,operator_required:true}),{Err:"upgrade_required"});
  }
  assert.equal(await schemaSnapshot(),v3);
  assert.equal(await db.prepare("SELECT name FROM sqlite_master WHERE name='auth_operator_bindings'").first(),null);
  cases.push("Actual generated v3 upgrade admits managed or disabled mode; operator-required rejects v3 without creating binding state");
  assert.deepEqual(await migrate("upgrade_operator"),{Ok:true});
  const v4=await schemaSnapshot();
  for(const managed_required of [false,true])for(const operator_required of [false,true])assert.deepEqual(await migrate("verify",{managed_required,operator_required}),{Ok:true});
  assert.equal(await schemaSnapshot(),v4);
  assert.deepEqual(await migrate("upgrade_operator"),{Ok:true});
  assert.equal(await schemaSnapshot(),v4);
  cases.push("Explicit generated operator upgrade reaches exact v4; all feature selections verify read-only and repeated upgrade is idempotent");
  extra=start("local-fresh-operator-account");
  const extraDb=await extra.getD1Database("ACCOUNT_DB");
  assert.deepEqual(await callOn(extra,{operation:"migration",action:"setup_operator"}),{Ok:true});
  const freshBefore=await schemaSnapshot(extraDb);
  assert.deepEqual(await callOn(extra,{operation:"migration",action:"verify",operator_required:true}),{Ok:true});
  assert.equal(await schemaSnapshot(extraDb),freshBefore);
  await extra.dispose();extra=undefined;
  cases.push("Actual generated explicit fresh operator setup creates v4 directly and read-only binding-required verification succeeds");

  assert.deepEqual(await read("binding_id","unknown"),{Ok:null});
  assert.deepEqual(await unchanged(()=>read("binding_id OR 1=1","unknown")),{Err:"storage"});
  assert.deepEqual(await unchanged(()=>prepare("source-missing","binding-missing","operator-missing")),{Err:"storage"});
  cases.push("Unknown binding is absent; owner rejects non-allowlisted read columns and missing identity FK without binding writes");
  await identity("operator-main");
  const raced=await Promise.all(Array.from({length:12},(_,i)=>prepare("source-main",`binding-candidate-${i}`,"operator-main")));
  assert.ok(raced.every(value=>value.Ok));
  const pending=raced[0].Ok;
  assert.ok(raced.every(value=>value.Ok.binding_id===pending.binding_id));
  assert.equal((await bindingRows()).length,1);
  assert.equal(pending.status,"pending");assert.equal(pending.revision,1);
  assert.equal(pending.audit_event_id,"");assert.equal(pending.policy_revision,"");assert.equal(pending.revocation_state,"none");
  assert.deepEqual((await read("source_subject","source-main")).Ok,pending);
  assert.deepEqual((await read("operator_subject","operator-main")).Ok,pending);
  cases.push("Twelve concurrent prepares for one source tuple return one stable pending binding and revision without premature activation receipts");
  assert.deepEqual((await unchanged(()=>prepare("source-main","replacement-candidate","operator-main"))).Ok,pending);
  assert.deepEqual((await unchanged(()=>activate(pending.binding_id,9,"wrong-revision"))).Ok,pending);
  assert.deepEqual((await unchanged(()=>complete(pending.binding_id,1,"too-early-complete"))).Ok,pending);
  cases.push("Pending prepare replay, wrong activation revision, and completion before revoke leave state and receipts unchanged");

  for(const patch of [{source_issuer:"other.issuer"},{deployment:"other-deployment"},{scope_kind:"other-kind"},{scope_id:"other-scope"}]){
    const other={...config,...patch};
    assert.deepEqual(await unchanged(()=>read("binding_id",pending.binding_id,other)),{Ok:null});
    assert.deepEqual(await unchanged(()=>read("source_subject","source-main",other)),{Ok:null});
    assert.deepEqual(await unchanged(()=>read("operator_subject","operator-main",other)),{Ok:null});
    assert.deepEqual(await unchanged(()=>activate(pending.binding_id,1,"foreign-audit","foreign-policy",other)),{Ok:null});
    assert.deepEqual(await unchanged(()=>revoke(pending.binding_id,"foreign-actor","2026-10-04T01:00:00Z",other)),{Ok:null});
    assert.deepEqual(await unchanged(()=>complete(pending.binding_id,1,"foreign-complete",other)),{Ok:null});
  }
  assert.deepEqual(await unchanged(()=>prepare("source-main","other-scope-candidate","operator-main",{...config,scope_id:"other-scope"})),{Err:"storage"});
  cases.push("Issuer, deployment, scope kind and scope ID isolate all reads and transitions; conflicting source tuple cannot be rebound through another scope");

  const activeRace=await Promise.all([activate(pending.binding_id,1,"activation-A","policy-A"),activate(pending.binding_id,1,"activation-B","policy-B")]);
  const active=(await read("binding_id",pending.binding_id)).Ok;
  assert.equal(active.status,"active");assert.equal(active.revision,1);
  assert.ok(["activation-A","activation-B"].includes(active.audit_event_id));
  assert.equal(active.policy_revision,active.audit_event_id==="activation-A"?"policy-A":"policy-B");
  assert.ok(activeRace.every(value=>value.Ok.status==="active"));
  assert.deepEqual((await unchanged(()=>activate(pending.binding_id,1,"replayed-audit","replayed-policy"))).Ok,active);
  cases.push("Concurrent activation CAS commits one coherent Audit/Access receipt pair; later activation cannot replace the first applied receipts");

  const actors=[{actor:"admin-A",occurred:"2026-10-04T02:00:00Z"},{actor:"admin-B",occurred:"2026-10-04T03:00:00Z"}];
  await Promise.all(actors.map(({actor,occurred})=>revoke(pending.binding_id,actor,occurred)));
  const revoked=(await read("binding_id",pending.binding_id)).Ok;
  assert.equal(revoked.status,"revoked");assert.equal(revoked.revision,2);assert.equal(revoked.revocation_state,"pending");
  assert.ok(actors.some(value=>value.actor===revoked.revoked_by&&value.occurred===revoked.revoked_at));
  assert.equal(revoked.audit_event_id,active.audit_event_id);assert.equal(revoked.policy_revision,active.policy_revision);
  assert.equal(revoked.revocation_audit_event_id,"");
  cases.push("Concurrent revoke advances revision exactly once and durably records one coherent actor/time plus pending revocation outbox state");
  assert.deepEqual((await unchanged(()=>revoke(pending.binding_id,"later-actor","2026-10-05T00:00:00Z"))).Ok,revoked);
  assert.deepEqual((await unchanged(()=>prepare("source-main","revive-candidate","operator-main"))).Ok,revoked);
  assert.deepEqual((await unchanged(()=>activate(pending.binding_id,1,"old-receipt"))).Ok,revoked);
  assert.deepEqual((await unchanged(()=>activate(pending.binding_id,2,"current-receipt"))).Ok,revoked);
  cases.push("Repeated revoke preserves original actor/time and revision; prepare or old/current activation cannot revive a revoked binding");
  assert.deepEqual((await unchanged(()=>complete(pending.binding_id,1,"wrong-complete"))).Ok,revoked);
  assert.deepEqual(await unchanged(()=>complete(pending.binding_id,2,"foreign-complete",{...config,scope_id:"foreign-scope"})),{Ok:null});
  await Promise.all([complete(pending.binding_id,2,"complete-A"),complete(pending.binding_id,2,"complete-B")]);
  const completed=(await read("binding_id",pending.binding_id)).Ok;
  assert.equal(completed.status,"revoked");assert.equal(completed.revision,2);assert.equal(completed.revocation_state,"complete");
  assert.ok(["complete-A","complete-B"].includes(completed.revocation_audit_event_id));
  assert.equal(completed.revoked_by,revoked.revoked_by);assert.equal(completed.revoked_at,revoked.revoked_at);
  assert.deepEqual((await unchanged(()=>complete(pending.binding_id,2,"replacement-complete"))).Ok,completed);
  cases.push("Revocation completion requires exact revision and scope; concurrent completion CAS keeps one durable Audit receipt and later retry cannot overwrite it");

  await identity("operator-second");await identity("operator-third");
  const secondCfg={...config,deployment:"second-deployment",scope_id:"second-scope"};
  const issuerCfg={...config,source_issuer:"second.accounts"};
  const second=(await prepare("source-main","binding-second","operator-second",secondCfg)).Ok;
  const third=(await prepare("source-main","binding-third","operator-third",issuerCfg)).Ok;
  assert.equal(second.status,"pending");assert.equal(third.status,"pending");
  assert.equal((await bindingRows()).length,3);
  assert.deepEqual((await read("source_subject","source-main")).Ok,completed);
  assert.deepEqual((await read("source_subject","source-main",secondCfg)).Ok,second);
  assert.deepEqual((await read("source_subject","source-main",issuerCfg)).Ok,third);
  cases.push("The same external subject in distinct issuers or deployments has separate operator identities and does not alias another scoped binding");
  await mf.dispose();mf=start("local-operator-account");db=await mf.getD1Database("ACCOUNT_DB");
  assert.deepEqual((await read("binding_id",pending.binding_id)).Ok,completed);
  assert.deepEqual(await migrate("verify",{operator_required:true}),{Ok:true});
  assert.deepEqual((await unchanged(()=>revoke(pending.binding_id,"after-restart","2026-10-06T00:00:00Z"))).Ok,completed);
  cases.push("Workerd restart preserves binding revision, first revoke actor/time and completed outbox receipt; replay cannot erase durable history");

  assert.deepEqual(await hashes(sourceFiles,repository),sourceHashes,"Owner source changed during proof; rerun against frozen source");
  assert.deepEqual(await hashes(fixtureFiles,root),fixtureHashes,"Fixture source changed during proof");
  const receipt={schema:"lenso.auth.operator-binding-local-d1@1",backend:"actual-local-workerd-d1",passed:true,cloudResourcesCreated:false,sourceHashes,fixtureHashes,toolVersions:{rustc:execFileSync(process.env.RUSTC??"rustc",["--version"],{encoding:"utf8"}).trim(),wasmBindgen:execFileSync(process.env.LENSO_WASM_BINDGEN??"wasm-bindgen",["--version"],{encoding:"utf8"}).trim(),wrangler:wranglerRequire("./package.json").version,miniflare:wranglerRequire("miniflare/package.json").version},scope:"Actual Account-owned storage/operator_binding.rs, generated migration v2/v3/v4 operators and owner D1 bridge. Store/Config/Record and request framing shims; synthetic identity seeds only. No Kernel, Capability projection, caller ACL, Access/Audit collaboration, session admission or browser/Ingress gate. Independent wasm-bindgen .127 fixture; actual Auth .128 App cohort requires separate qualification.",cases};
  if(receiptPath)await writeFile(receiptPath,JSON.stringify(receipt,null,2)+"\n");
  process.stdout.write(JSON.stringify(receipt,null,2)+"\n");
} finally {
  await extra?.dispose();await mf?.dispose();
  await rm(output,{force:true});await rm(persistence,{recursive:true,force:true});
}
