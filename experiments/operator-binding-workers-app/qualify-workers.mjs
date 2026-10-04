import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('.',import.meta.url));
const repository=resolve(root,'../..');
const cargo=process.env.LENSO_CARGO??'cargo';
const require=createRequire(process.env.LENSO_WRANGLER_PACKAGE??import.meta.url);
const wranglerPackage=require.resolve('wrangler/package.json');
const wranglerRequire=createRequire(wranglerPackage);
const {Miniflare,convertV4MiniflareOptions}=wranglerRequire('miniflare');
const {build}=wranglerRequire('esbuild');
const runtimePackage=process.env.LENSO_WORKERS_RUNTIME_PACKAGE??require.resolve('@lenso/workers-runtime');
const toolVersions=Object.fromEntries(await Promise.all([['miniflare',wranglerRequire.resolve('miniflare/package.json')],['workerd',wranglerRequire.resolve('workerd/package.json')],['workers_runtime',join(dirname(runtimePackage),'package.json')]].map(async([name,path])=>[name,JSON.parse(await readFile(path,'utf8')).version])));
const metadata=JSON.parse(execFileSync(cargo,['metadata','--locked','--offline','--format-version','1','--filter-platform','wasm32-unknown-unknown'],{cwd:root,encoding:'utf8'}));
const ownerPath=name=>dirname(metadata.packages.find(p=>p.name===name).manifest_path);
const accessModule=join(ownerPath('lenso-access-control-d1-plugin'),'src/host_facilities/state.mjs');
const auditModule=join(ownerPath('lenso-audit-log-d1-plugin'),'src/host_facilities/store.mjs');
const output=resolve(root,'.proof.bundle.mjs');
const persistence=await mkdtemp(join(tmpdir(),'lenso-operator-binding-app-'));
const receipt=process.argv[2];
if(receipt&&resolve(receipt).startsWith(repository))throw new Error('receipt must be outside source worktree');
const origin='https://synthetic.example';
const SOURCE='lenso.auth.account/accounts',OPERATORS='lenso.auth.account/operators';
const OWNER='test.operator-binding-app/owner',ORDINARY='test.operator-binding-app/ordinary',BROWSER='test.operator-binding-app/operators-browser';
const cases=[];
const faultObservations=[];
let mf,db,owner,ownerSession,ordinary,ordinarySession;
const pass=name=>{cases.push(name);console.log(`passed: ${name}`);};
const hash=buffer=>createHash('sha256').update(buffer).digest('hex');
async function call(operation,args={}) {
  const response=await mf.dispatchFetch(origin+'/fixture/invoke',{method:'POST',body:JSON.stringify({owner_subject:owner??'public-placeholder',operation,...args})});
  assert.equal(response.status,200,`actual synthetic App ${operation} HTTP bridge failed`);
  return response.json();
}
const ok=async(operation,args={})=>{const result=await call(operation,args);assert.ok(result.Ok,`actual ${operation} domain failed: ${JSON.stringify(result)}`);return result.Ok;};
const denied=async(operation,args,error)=>assert.equal((await call(operation,args)).Err,error,`${operation} expected denial`);
const sql=(database,statement,...params)=>db[database].prepare(statement).bind(...params).run();
const scalar=async(database,statement,...params)=>Object.values(await db[database].prepare(statement).bind(...params).first())[0];
const bindingStatus=()=>scalar('operators','SELECT status FROM auth_operator_bindings');
const sessions=()=>scalar('operators','SELECT count(*) FROM auth_sessions');
const closedAuth=async(token,args={})=>assert.ok((await call('authenticate',{caller:BROWSER,credential:token,...args})).Err,'old operators Auth must reject');
const inspected=async(session,args={})=>ok('inspect',{session_id:session.session_id,...args});
async function start(scenario) {
  if(mf)await mf.dispose();
  mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:persistence,workers:[{
    name:'operator-binding-app-proof',modules:[{type:'ESModule',path:output},{type:'CompiledWasm',path:resolve(root,'pkg/operator_binding_app_bg.wasm')}],modulesRoot:root,
    compatibilityDate:'2026-07-08',d1Databases:Object.fromEntries(['ACCOUNTS','OPERATORS','ACCESS','AUDIT'].map(name=>[name+'_DB',`local-operator-${scenario}-${name}`])),
  }]}));
  db=Object.fromEntries(await Promise.all(['accounts','operators','access','audit'].map(async name=>[name,await mf.getD1Database(name.toUpperCase()+'_DB')])));
  owner=undefined;
  assert.equal((await mf.dispatchFetch(origin+'/fixture/migrate',{method:'POST'})).status,200,'explicit actual owner migrations failed');
  owner=(await ok('ensure',{label:'confirmed-owner'})).subject;
  ordinary=(await ok('ensure',{label:'ordinary-user'})).subject;
  ownerSession=await ok('issue',{subject:owner});
  ordinarySession=await ok('issue',{subject:ordinary});
}
async function storageFault(operation,args,expected) {
  const result=await call(operation,args);
  assert.ok(result.Err===expected||['plugin_failure','admission_closed'].includes(result.Runtime?.kind),'fault must surface real domain/outer runtime failure');
  assert.equal(result.admission_after_failure,'closed','real Kernel must close admission after actual owner storage fault');
  assert.ok(['clean','runtime_failure'].includes(result.shutdown),'actual shutdown outcome must be recorded without rewriting');
  faultObservations.push({operation,expected,domain_error:result.Err??null,outer_runtime_failure:result.Runtime??null,admission:result.admission_after_failure,shutdown:result.shutdown});
}
async function failAudit(action) {
  await sql('audit',`CREATE TRIGGER fixture_fail BEFORE INSERT ON audit_events WHEN NEW.event_name='auth.operator-binding.${action}' BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END`);
}
try {
  execFileSync(cargo,['build','--locked','--offline','--target','wasm32-unknown-unknown','--release'],{cwd:root,stdio:'inherit'});
  const bindgen=process.env.LENSO_WASM_BINDGEN??'wasm-bindgen';
  assert.equal(execFileSync(bindgen,['--version'],{encoding:'utf8'}).trim(),'wasm-bindgen 0.2.127');
  execFileSync(bindgen,['--target','web','--out-dir','pkg','--out-name','operator_binding_app','target/wasm32-unknown-unknown/release/lenso_operator_binding_workers_app_proof.wasm'],{cwd:root,stdio:'inherit'});
  await build({entryPoints:[resolve(root,'proof-worker.mjs')],outfile:output,bundle:true,format:'esm',platform:'browser',target:'es2022',plugins:[
    {name:'wasm',setup(b){b.onResolve({filter:/\.wasm$/},a=>({path:a.path,external:true}));}},
    {name:'owners',setup(b){b.onResolve({filter:/^(@lenso\/workers-runtime|@fixture\/access-state|@fixture\/audit-store)$/},a=>({path:{'@lenso/workers-runtime':runtimePackage,'@fixture/access-state':accessModule,'@fixture/audit-store':auditModule}[a.path]}));}},
  ]});
  await start('success');
  const enabled=(await ok('resolve')).bindings;
  const directory='lenso.identity.directory@1';
  assert.equal(enabled.filter(b=>b.consumer_instance===SOURCE&&b.capability_id===directory).length,0);
  const selected=enabled.filter(b=>b.consumer_instance===OPERATORS&&b.capability_id===directory);
  assert.equal(selected.length,1);assert.equal(selected[0].provider_instance,SOURCE);
  const disabled=await ok('resolve',{disabled:true});
  assert.equal(disabled.bindings.filter(b=>[SOURCE,OPERATORS].includes(b.consumer_instance)&&b.capability_id===directory).length,0);
  const sourceConfig=JSON.parse(disabled.instances.find(i=>i.instance_key===SOURCE).configuration);
  const operatorConfig=JSON.parse(disabled.instances.find(i=>i.instance_key===OPERATORS).configuration);
  assert.equal(sourceConfig.storage_ref,'auth/accounts');assert.equal(operatorConfig.storage_ref,'auth/operators');
  assert.equal(sourceConfig.database_url_secret,'');assert.equal(sourceConfig.d1_binding,'');
  assert.deepEqual(enabled.filter(b=>b.consumer_instance==='lenso.auth.operator-session/default').map(b=>b.requirement_id).sort(),['accounts_state','access','access_admin','audit','bindings','operators_issuer','operators_state'].sort());
  pass('Actual owner PLUGIN_DESCRIPTOR_JSON through HostCatalog/PluginRoot: source empty optional Slot, enabled operators exact Source, disabled operators empty Slot; seven named workflow dependencies; logical Account refs');
  await denied('exchange',{caller:ORDINARY,credential:ordinarySession.credential},'not_active');
  await denied('bootstrap',{caller:ORDINARY,credential:ownerSession.credential},'permission_denied');
  await denied('bootstrap',{credential:ordinarySession.credential},'permission_denied');
  assert.equal(await scalar('operators','SELECT count(*) FROM auth_operator_bindings'),0);assert.equal(await sessions(),0);
  pass('Unbound ordinary user, wrong local caller and wrong confirmed owner subject cannot exchange/bootstrap or write operators state');
  const binding=await ok('bootstrap',{credential:ownerSession.credential});
  assert.equal(binding.active,true);assert.equal(binding.source_subject,owner);assert.notEqual(binding.operator_subject,owner);assert.equal(binding.source_issuer,'synthetic.accounts');assert.equal(binding.scope_id,'synthetic');
  assert.equal(await bindingStatus(),'active');
  assert.equal(await scalar('audit',"SELECT count(*) FROM audit_events WHERE event_name IN ('auth.operator-binding.requested','auth.operator-binding.applied')"),2);
  const role=await ok('role',{binding_id:binding.binding_id});assert.equal(role.protected,false);
  assert.deepEqual(role.permissions.sort(),['synthetic.settings.write','access-control.bindings.manage','lenso.auth.operator-login'].sort());
  for(const [permission,allowed] of [['synthetic.settings.write',true],['synthetic.billing.delete',false]])assert.equal((await ok('permission',{subject:binding.operator_subject,permission})).allowed,allowed);
  await denied('permission',{subject:binding.operator_subject,permission:'*'},'invalid_request');
  await denied('bootstrap',{credential:ownerSession.credential},'bootstrap_consumed');
  pass('Actual Access protected bootstrap plus finite operator business/login role; real requested/applied Audit persisted before activation; one-time owner bootstrap');
  const session=await ok('exchange',{credential:ownerSession.credential});
  const actor=(await ok('authenticate',{caller:BROWSER,credential:session.credential})).assertion;
  assert.equal(actor.issuer,'synthetic.operators');assert.equal(actor.subject,binding.operator_subject);assert.equal((await inspected(session)).active,true);
  assert.ok((await call('authenticate',{credential:session.credential})).Err);
  await closedAuth(ordinarySession.credential);
  await denied('revoke',{credential:ordinarySession.credential,binding_id:binding.binding_id},'unauthenticated');
  pass('Generated exchange/Auth/Inspect produces distinct operators realm; cross-realm credentials and ordinary source assertion cannot authorize revocation');
  const n=await sessions();
  await sql('access',"DELETE FROM access_control_role_permissions WHERE permission='lenso.auth.operator-login'");
  await denied('exchange',{credential:ownerSession.credential},'not_active');assert.equal(await sessions(),n);
  await sql('access',"INSERT INTO access_control_role_permissions(scope_kind,scope_id,role_id,permission) SELECT scope_kind,scope_id,role_id,'lenso.auth.operator-login' FROM access_control_roles WHERE role_id LIKE 'operator-binding.%'");
  pass('Live Access login permission removal prevents new operator credential issuance');
  await closedAuth(session.credential,{disabled:true});assert.equal((await inspected(session,{disabled:true})).active,false);
  await ok('source_status',{subject:owner,source_disabled:true});
  await closedAuth(session.credential);assert.equal((await inspected(session)).active,false);
  await ok('source_status',{subject:owner,source_disabled:false});
  pass('Binding feature disable and live Source Account disable reject old operators Auth/Inspect through freshly resolved Apps');
  await denied('revoke',{caller:BROWSER,credential:session.credential,binding_id:binding.binding_id,narrowed:true},'permission_denied');assert.equal(await bindingStatus(),'active');
  await sql('access',"DELETE FROM access_control_role_permissions WHERE permission='access-control.bindings.manage'");
  await denied('revoke',{caller:BROWSER,credential:session.credential,binding_id:binding.binding_id},'permission_denied');assert.equal(await bindingStatus(),'active');
  await sql('access',"INSERT INTO access_control_role_permissions(scope_kind,scope_id,role_id,permission) SELECT scope_kind,scope_id,role_id,'access-control.bindings.manage' FROM access_control_roles WHERE protected=1");
  pass('Narrowed credential ceiling and removed scoped Access management permission each forbid revocation without state changes');
  await failAudit('revoked');
  await storageFault('revoke',{caller:BROWSER,credential:session.credential,binding_id:binding.binding_id},'audit_unavailable');
  assert.equal(await bindingStatus(),'revoked');assert.equal(await scalar('operators','SELECT revocation_state FROM auth_operator_bindings'),'pending');
  await closedAuth(session.credential);assert.equal((await inspected(session)).active,false);
  pass('Actual Audit D1 insert fault preserves durable revoked denial and pending outbox; fresh App rejects old credentials');
  await sql('audit','DROP TRIGGER fixture_fail');
  // Source disable revoked the earlier source session; recovery requires a new real source login.
  ownerSession=await ok('issue',{subject:owner});
  await denied('recover',{caller:ORDINARY,credential:ownerSession.credential,binding_id:binding.binding_id},'permission_denied');
  const recovered=await ok('recover',{credential:ownerSession.credential,binding_id:binding.binding_id});
  assert.equal(recovered.revoked,true);assert.equal(recovered.active,false);assert.equal(recovered.revocation_pending,false);assert.ok(recovered.revocation_audit_event_id);assert.equal(recovered.revoked_by,binding.operator_subject);
  await closedAuth(session.credential);await denied('exchange',{credential:ownerSession.credential},'not_active');
  pass('Fresh event controlled exact source-owner recovery drains real Audit outbox, preserves original revoker and never restores login');
  for(const fault of ['audit','access']) {
    await start(fault);
    if(fault==='audit')await failAudit('applied');
    else await sql('access',"CREATE TRIGGER fixture_fail BEFORE INSERT ON access_control_roles WHEN NEW.role_id LIKE 'operator-binding.%' BEGIN SELECT RAISE(ABORT,'synthetic Access unavailable'); END");
    await storageFault('bootstrap',{credential:ownerSession.credential},fault+'_unavailable');
    assert.equal(await bindingStatus(),'pending');
    await denied('exchange',{credential:ownerSession.credential},'not_active');assert.equal(await sessions(),0);
    pass(`Actual ${fault} D1 write fault leaves pending binding; fresh App denies exchange with zero operator sessions`);
  }
  const evidence={qualification:'actual_workerd_synthetic_app',passed:cases.length,cases,faultObservations,cohort:{...toolVersions,kernel:'0.3.12',facade:'0.5.29',wasm_bindgen:'0.2.127',js_sys:'0.3.104',wasm_bindgen_futures:'0.4.77',access_git:'94b6d06cff1e6f17a06e771df232f662cae28ad5',audit_git:'83b4e52e8c6eaf2bbe5356dccd1e3a59b872c8e9',wrangler:JSON.parse(await readFile(wranglerPackage,'utf8')).version,node:process.version},host:{resolution:'actual owner Descriptors -> HostCatalog -> PluginRoot',empty_slot:'HostSlot::optional(source_accounts)',operators_enabled:'exact Source Account',operators_disabled:'empty source_accounts Slot',storage:'logical Account refs and target private matching D1 attachments'},limits:['Synthetic public RuntimeDriver performs mechanical task/timer work; not older WorkersDriver package qualification','Private synthetic request bridge uses protocol-neutral generated APIs; no Relay/HTTP ingress/CSRF qualification','Access and Audit retain external-owner legacy facility/configuration interfaces','No identical serialized Native/Workers graph claim; Native fixture is separate','No production credentials, database, migrations or deployment'],sha256:{wasm:hash(await readFile(resolve(root,'pkg/operator_binding_app_bg.wasm'))),cargo_lock:hash(await readFile(resolve(root,'Cargo.lock'))),package_lock:hash(await readFile(resolve(root,'package-lock.json'))),auth_owner_js:hash(await readFile(resolve(repository,'crates/lenso-auth-account-plugin/src/host_facilities/state.mjs'))),access_owner_js:hash(await readFile(accessModule)),audit_owner_js:hash(await readFile(auditModule))}};
  if(receipt)await writeFile(receipt,JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify({passed:cases.length,cases}));
} finally {if(mf)await mf.dispose();await rm(persistence,{recursive:true,force:true});await rm(output,{force:true});}
