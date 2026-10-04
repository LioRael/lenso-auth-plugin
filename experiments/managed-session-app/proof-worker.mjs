// Local synthetic framing. Real Ingress/Kernel/Auth execute inside actual Wasm.
import { initSync, invoke, migrate } from "./pkg/managed_session_app.js";
import wasmModule from "./pkg/managed_session_app_bg.wasm";
import { createEventScope } from "@lenso/workers-runtime";
import { createD1Binding } from "../../workers/d1-binding.mjs";
initSync({ module: wasmModule });
export default {
  async fetch(request, env) {
    const scope = createEventScope();
    const resources = {
      accountBatch: createD1Binding(env.ACCOUNT_DB, scope),
      passwordBatch: createD1Binding(env.PASSWORD_DB, scope),
    };
    try {
      const url = new URL(request.url);
      if (url.pathname === "/fixture/migrate") {
        await migrate(resources);
        return Response.json({ migrated: true });
      }
      const privateOperation = url.pathname === "/fixture/invoke";
      const input = privateOperation ? await request.json() : {
        operation: "http", method: request.method,
        uri: url.pathname + url.search, headers: [...request.headers],
      };
      input.tightened_policy=request.headers.get("x-local-proof-policy")==="tighter";
      const result = JSON.parse(await invoke(JSON.stringify(input), resources));
      if (privateOperation) return Response.json(result, { headers: { "cache-control": "no-store" } });
      // Test transport loss after a successful rotation, without re-executing it.
      if (request.headers.get("x-local-drop-response") === "after-rotation" && result.status === 200) {
        return new Response(null, { status: 599, headers: { "cache-control": "no-store" } });
      }
      const headers = new Headers();
      for (const [name, value] of result.headers) headers.append(name, value);
      return new Response(JSON.stringify(result.body), { status: result.status, headers });
    } catch {
      return Response.json({ error: "synthetic_app_runtime_failure" }, { status: 500 });
    } finally {
      if (!(await scope.settled())) throw new Error("synthetic App settlement unconfirmed");
    }
  },
};
