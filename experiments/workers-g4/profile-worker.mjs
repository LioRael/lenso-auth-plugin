// Never a Wrangler entry point. Only the local D01 harness loads this module.
import { initSync, __wbg_reset_state, profile_invoke, migrate } from './pkg/lenso_workers_g4_host.js';
import module from './pkg/lenso_workers_g4_host_bg.wasm';
import { createEventRunner } from '@lenso/workers-runtime/runner';
import { createEventScope } from '@lenso/workers-runtime';
import { clearTimers } from './clock.mjs';
import { createD1Binding } from '../../workers/d1-binding.mjs';
import { counters, observeDatabase } from './profile-observations.mjs';

let exports, generation = 0;
const runner = createEventRunner({
  instantiate() { exports = initSync({ module }); generation++; return exports; },
  resetState: __wbg_reset_state, clearTimers, eventLimitMs: 15000,
});
const owners = [
  ['account', 'ACCOUNT_DB', 'accountBatch'], ['oauth-flow', 'OAUTH_DB', 'oauthBatch'],
  ['password', 'PASSWORD_DB', 'passwordBatch'], ['phone', 'PHONE_DB', 'phoneBatch'],
  ['device', 'DEVICE_DB', 'deviceBatch'], ['api-token', 'API_TOKEN_DB', 'apiBatch'],
  ['oidc', 'OIDC_DB', 'oidcBatch'],
];
export default {
  async fetch(request, env) {
    const input = await request.json();
    const observations = { d1: {}, memory: [], generation_before: generation };
    const memory = phase => observations.memory.push({ phase, generation, bytes: exports.memory.buffer.byteLength });
    memory('before_event');
    const scope = createEventScope(resources => ({
      ...env.SECRETS,
      ...Object.fromEntries(owners.filter(([, binding]) => env[binding]).map(([owner, binding, name]) => {
        const count = observations.d1[owner] = counters();
        const database = observeDatabase(env[binding], count, {
          fail: input.fault === 'storage' && owner === 'account',
          memory: () => memory('d1_boundary'),
        });
        return [name, createD1Binding(database, resources)];
      })),
    }));
    let result, status = 200;
    try {
      result = await runner.run(async () => {
        memory('operation_entry');
        if (input.fault === 'abandon') throw new Error('local D01 controlled abandonment');
        if (input.operation === 'setup') {
          for (const [owner, binding, batch] of owners) {
            if (env[binding]) await migrate(owner, 'setup', scope[batch]);
          }
          return JSON.stringify({ setup: true });
        }
        return profile_invoke(JSON.stringify(input), scope);
      }, { scope, signal: request.signal });
    } catch {
      status = 503;
      result = { runtime_failure: true }; // Never include errors, inputs or secret material.
    }
    memory('after_event');
    observations.generation_after = generation;
    return Response.json({ result, observations }, { status, headers: { 'cache-control': 'no-store' } });
  },
};
