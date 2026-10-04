// Local-only storage framing. No production route, credential or account.
import {initSync, invoke} from "./pkg/operator_binding_d1.js";
import wasmModule from "./pkg/operator_binding_d1_bg.wasm";
import {createEventScope} from "@lenso/workers-runtime";
import {createD1Binding} from "../../workers/d1-binding.mjs";

initSync({module:wasmModule});
export default {
  async fetch(request, env) {
    if(request.method!=="POST") return new Response(null,{status:405});
    const scope=createEventScope();
    try {
      const result=JSON.parse(await invoke(await request.text(),createD1Binding(env.ACCOUNT_DB,scope)));
      return Response.json(result,{headers:{"cache-control":"no-store"}});
    } catch {
      return Response.json({runtime_failure:"storage"},{status:500});
    } finally {
      if(!(await scope.settled()))throw new Error("local storage cleanup unconfirmed");
    }
  },
};
