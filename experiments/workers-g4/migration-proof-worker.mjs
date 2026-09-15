// Local-only migration qualification. Never configured as a deployed entry point.
import * as generated from './pkg/lenso_workers_g4_host.js';
import wasmModule from './pkg/lenso_workers_g4_host_bg.wasm';
import { createWorkersHttpHost, createEventScope } from '@lenso/workers-runtime';
import { createD1Binding } from '../../workers/d1-binding.mjs';

export default createWorkersHttpHost({
  bindings: {
    ...generated,
    async handle_http(_input, scope) {
      await generated.migrate(scope.owner, scope.action, scope.batch);
      return JSON.stringify({
        status: 200, headers: [],
        body: Array.from(new TextEncoder().encode('{"ok":true}')),
        shutdown: 'clean',
      });
    },
  },
  wasmModule,
  limits: { eventLimitMs: 10000 },
  createScope(request, env) {
    const url = new URL(request.url);
    const binding = url.searchParams.get('binding');
    if (!Object.hasOwn(env, binding)) throw new Error('Unknown proof binding');
    return createEventScope(resources => ({
      owner: url.searchParams.get('owner'),
      action: url.searchParams.get('action'),
      batch: createD1Binding(env[binding], resources),
    }));
  },
});
