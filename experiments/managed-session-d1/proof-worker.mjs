// Local-only framing for actual Rust Account D1 Store operations. No production
// routes, bindings or credentials are used. This is a storage runtime fixture.
import { initSync, invoke } from "./pkg/managed_session_d1.js";
import wasmModule from "./pkg/managed_session_d1_bg.wasm";
import { createEventScope } from "@lenso/workers-runtime";
import { createD1Binding } from "../../workers/d1-binding.mjs";

initSync({ module: wasmModule });

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response(null, {status:405});
    const scope = createEventScope();
    let outcome;
    try {
      outcome = JSON.parse(await invoke(await request.text(), createD1Binding(env.ACCOUNT_DB,scope)));
      // Exercise post-commit response loss without reissuing/redoing a mutation.
      if (request.headers.get("x-local-drop-response") === "after-rotation") {
        return new Response(null,{status:599,headers:{"cache-control":"no-store"}});
      }
      return Response.json(outcome,{headers:{"cache-control":"no-store"}});
    } catch {
      // Do not include SQL parameters, credentials or arbitrary exception text.
      return Response.json({runtime_failure:"storage"},{status:500});
    } finally {
      if (!(await scope.settled())) throw new Error("local storage cleanup unconfirmed");
    }
  },
};
