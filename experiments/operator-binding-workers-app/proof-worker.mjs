// Synthetic event framing; all business calls execute through real Kernel and owner code.
import { initSync, invoke, migrate } from './pkg/operator_binding_app.js';
import wasmModule from './pkg/operator_binding_app_bg.wasm';
import { createEventScope } from '@lenso/workers-runtime';
import { create as authState } from '../../crates/lenso-auth-account-plugin/src/host_facilities/state.mjs';
import { create as accessState } from '@fixture/access-state';
import { create as auditStore, setup as auditSetup } from '@fixture/audit-store';
initSync({module:wasmModule});
export default {
  async fetch(request,env) {
    const scope=createEventScope();
    const migration=new URL(request.url).pathname==='/fixture/migrate';
    const input=migration?null:await request.json();
    const access=accessState(env.ACCESS_DB,scope,{profile:'workers-d1',binding:'ACCESS_DB'});
    // Synthetic latency only: commit the real owner batch, then delay its reply.
    // Keep the delay tracked by the real event scope and preserve the receipt.
    const accessWithDelay=input?.fixture_scope_delay_ms===6000?Object.freeze({
      ...access,
      batch:statements=>scope.run(async()=>{
        const result=await access.batch(statements);
        if(JSON.parse(statements).some(({sql})=>sql.startsWith('INSERT INTO access_control_scopes('))) {
          await new Promise(resolve=>setTimeout(resolve,6000));
        }
        return result;
      }),
    }):access;
    const resources={
      accounts:authState(env.ACCOUNTS_DB,scope,{profile:'workers-d1',binding:'ACCOUNTS_DB',storage_ref:'auth/accounts'}),
      operators:authState(env.OPERATORS_DB,scope,{profile:'workers-d1',binding:'OPERATORS_DB',storage_ref:'auth/operators'}),
      access:accessWithDelay,
      audit:auditStore(env.AUDIT_DB,scope,{profile:'workers-d1'}),
    };
    try {
      if(migration) {
        await auditSetup(env.AUDIT_DB);
        await migrate(resources);
        return Response.json({migrated:true});
      }
      return Response.json(JSON.parse(await invoke(JSON.stringify(input),resources)),{headers:{'cache-control':'no-store'}});
    } catch(error) {
      console.error(String(error));
      return Response.json({error:'synthetic_operator_app_runtime_failure'},{status:500});
    } finally {
      if(!(await scope.settled())) throw new Error('synthetic event settlement unconfirmed');
    }
  }
};
