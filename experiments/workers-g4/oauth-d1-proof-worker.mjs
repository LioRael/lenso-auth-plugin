// Local-only OAuth/D1 composition entry point. It keeps the actual generated
// Rust Host, Kernel, Capability route, and Workers factory intact while the
// harness owns only ephemeral D1 resources and HTTP test framing.
import * as generated from "./pkg/lenso_workers_g4_host.js";
import wasmModule from "./pkg/lenso_workers_g4_host_bg.wasm";
import { createWorkersHttpHost, createEventScope } from "@lenso/workers-runtime";
import { createD1Binding } from "../../workers/d1-binding.mjs";

const encoder = new TextEncoder();

function response(status, value) {
  return JSON.stringify({
    status,
    headers: [["content-type", "application/json"], ["cache-control", "no-store"]],
    body: [...encoder.encode(JSON.stringify(value))],
    shutdown: "clean",
  });
}

function inputBody(input) {
  const envelope = JSON.parse(input);
  if (!Array.isArray(envelope.body)) throw new Error("missing OAuth proof request body");
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(envelope.body)));
}

function migrationBinding(env, binding) {
  if (binding !== "ACCOUNT_DB" && binding !== "OAUTH_DB") {
    throw new Error("unknown OAuth proof D1 binding");
  }
  return env[binding];
}

export default createWorkersHttpHost({
  bindings: {
    ...generated,
    async handle_http(input, scope) {
      if (scope.mode === "migration") {
        await generated.migrate(scope.owner, scope.action, scope.batch);
        return response(200, { ok: true });
      }
      const request = inputBody(input);
      const result = JSON.parse(await generated.invoke(JSON.stringify(request), scope));
      // This private proof switch is intentionally outside Auth's operation
      // payload. It runs the actual generated consume path first, then withholds
      // its application response so the harness can prove retry reconciliation
      // from the durable D1 terminal state. The normal G4 Worker entry point
      // neither reads nor exposes this header.
      if (scope.dropResponseAfterConsume && request.operation === "consume") {
        throw new Error("local proof response dropped after durable consume result");
      }
      return response(200, result);
    },
  },
  wasmModule,
  limits: {
    eventLimitMs: 15_000,
    maxRequestBodyBytes: 65_536,
    maxResponseBodyBytes: 65_536,
    maxRequestHeadBytes: 16_384,
    bodyReadTimeoutMs: 10_000,
  },
  createScope(request, env) {
    const url = new URL(request.url);
    const isMigration = url.pathname === "/migration";
    return createEventScope((resources) => {
      const accountBatch = createD1Binding(env.ACCOUNT_DB, resources);
      const oauthBatch = createD1Binding(env.OAUTH_DB, resources);
      return {
        mode: isMigration ? "migration" : "operation",
        owner: isMigration ? url.searchParams.get("owner") : undefined,
        action: isMigration ? url.searchParams.get("action") : undefined,
        batch: isMigration
          ? createD1Binding(migrationBinding(env, url.searchParams.get("binding")), resources)
          : undefined,
        signing: env.SIGNING_KEY,
        pepper: env.TOKEN_PEPPER,
        oauth: env.OAUTH_KEY,
        otp: env.OTP_SECRET,
        providerSigning: env.PROVIDER_SIGNING_KEY,
        providerJwks: env.PROVIDER_JWKS,
        origin: url.origin,
        dropResponseAfterConsume:
          request.headers.get("x-lenso-local-proof-drop-response") === "after-consume-result",
        accountBatch,
        oauthBatch,
      };
    });
  },
});
