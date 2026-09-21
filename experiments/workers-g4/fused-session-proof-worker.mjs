// Local-only Task 8 composition entry point. Real HTTP still crosses Web's
// buffered ingress Host and the generated Rust `handle_http` export; this
// wrapper adds only ephemeral migration framing and a receipt header for the
// local Miniflare cohort. It is not a deployable Worker configuration.
import * as generated from "./pkg/lenso_workers_g4_host.js";
import wasmModule from "./pkg/lenso_workers_g4_host_bg.wasm";
import { createEventScope, createWorkersHttpHost } from "@lenso/workers-runtime";
import { createD1Binding } from "../../workers/d1-binding.mjs";
import { createScopedHttpFetch } from "@lenso/http-egress-workers";

const encoder = new TextEncoder();

function envelope(status, value) {
  return JSON.stringify({
    status,
    headers: [
      ["content-type", "application/json"],
      ["cache-control", "no-store"],
    ],
    body: [...encoder.encode(JSON.stringify(value))],
    shutdown: "clean",
  });
}

function migrationBinding(env, owner) {
  if (owner === "account") return env.ACCOUNT_DB;
  if (owner === "oauth-flow") return env.OAUTH_DB;
  throw new Error("unknown local composition migration owner");
}

async function handleHttp(input, scope) {
  if (scope.mode === "migration") {
    await generated.migrate(scope.owner, scope.action, scope.batch);
    return envelope(200, { ok: true });
  }
  return generated.handle_http(input, scope);
}

const http = createWorkersHttpHost({
  bindings: { ...generated, handle_http: handleHttp },
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
    const migration = url.pathname === "/_local/migration";
    const scopedFetch = async (input, options) => {
      const candidate = new Request(input, options);
      const target = new URL(candidate.url);
      // The fixture runs as a separate local workerd service. The generated
      // HTTP Egress capability still owns the request/response exchange; only
      // Miniflare's unavailable same-origin network loopback is replaced by
      // the platform-equivalent service-binding transport.
      if (target.origin === url.origin && target.pathname.startsWith("/fixture/")) {
        return env.IDP.fetch(candidate);
      }
      return fetch(candidate);
    };
    return createEventScope((resources) => ({
      mode: migration ? "migration" : "http",
      owner: migration ? url.searchParams.get("owner") : undefined,
      action: migration ? url.searchParams.get("action") : undefined,
      batch: migration
        ? createD1Binding(migrationBinding(env, url.searchParams.get("owner")), resources)
        : undefined,
      signing: env.SIGNING_KEY,
      pepper: env.TOKEN_PEPPER,
      oauth: env.OAUTH_KEY,
      oidc: env.OIDC_SECRET,
      origin: url.origin,
      accountBatch: createD1Binding(env.ACCOUNT_DB, resources),
      oauthBatch: createD1Binding(env.OAUTH_DB, resources),
      httpFetch: createScopedHttpFetch(resources, {
        fetch: scopedFetch,
        setTimeout,
        clearTimeout,
      }),
    }));
  },
  onReceipt(receipt, response) {
    if (receipt.ready === true && receipt.shutdown === "clean") {
      // This header is emitted only after the generated Host reports the one
      // Kernel App reached Ready and shut down cleanly for that ingress event.
      response.headers.set("x-lenso-local-app-lifecycle", "ready-clean");
    }
  },
});

export default {
  async fetch(request, env, ctx) {
    if (request.headers.get("x-proof-key") !== env.PROOF_KEY) {
      return new Response("Not found", { status: 404 });
    }
    return http.fetch(request, env, ctx);
  },
};
