// A real local-workerd cohort for Auth's Workers PostgreSQL transport seam.
// The worker loads generated Rust/Wasm and starts a new Kernel App for every
// operation. The JavaScript map below is only a Host-owned stand-in for a
// private PostgreSQL resource; it tests the callback boundary, not Hyperdrive.
import {
  __wbg_reset_state,
  initSync,
  oauth_postgres_invoke,
} from "./pkg/lenso_workers_g4_host.js";
import module from "./pkg/lenso_workers_g4_host_bg.wasm";
import { createEventRunner, createEventScope } from "@lenso/workers-runtime";
import { clearTimers } from "./clock.mjs";
import {
  createOAuthPostgresStore,
  createOAuthPostgresTransport,
} from "../../workers/postgres-transport.mjs";

const runner = createEventRunner({
  instantiate: () => initSync({ module }),
  resetState: __wbg_reset_state,
  clearTimers,
  eventLimitMs: 15_000,
});
const store = createOAuthPostgresStore();

function check(condition, detail) {
  if (!condition) throw new Error(detail);
}

function future(minutes = 5) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

async function invoke(operation, request, options = {}) {
  const transport = createOAuthPostgresTransport(store, options);
  const scope = createEventScope(() => ({
    oauth: "0123456789abcdef0123456789abcdef",
    oauthPostgres: transport.execute,
  }));
  const result = await runner.run(
    () =>
      oauth_postgres_invoke(
        JSON.stringify({
          operation,
          request,
          factory_conflict: options.factoryConflict === true,
        }),
        scope,
      ),
    { scope },
  );
  return {
    result: typeof result === "string" ? JSON.parse(result) : result,
    transport,
  };
}

async function create() {
  const response = await invoke("create", {
    provider: "github",
    return_to: "/settings/security",
    expires_at: future(),
  });
  check(
    response.result.outcome.Ok?.state,
    `OAuth create result shape ${JSON.stringify({
      ready: response.result.ready,
      shutdown: response.result.shutdown,
      outcomeKeys: Object.keys(response.result.outcome || {}).sort(),
      domain: response.result.outcome?.Err ?? null,
      runtimeFailure: response.result.outcome?.RuntimeFailure ?? null,
      transportCalls: response.transport.calls,
    })}`,
  );
  return response;
}

export default {
  async test() {
    const cases = [];
    const run = async (name, assertion) => {
      await assertion();
      cases.push({ name, passed: true });
    };
    try {
      await run("create", async () => {
        const created = await create();
        check(created.result.ready, "create must activate a ready App");
        check(created.result.shutdown === "clean", "create must shut down cleanly");
        check(
          created.transport.calls.every(
            ({ keys }) =>
              !keys.includes("d1_binding") && !keys.includes("database_url_secret"),
          ),
          "Auth transport protocol must not expose infrastructure selection",
        );
      });

      await run("consume", async () => {
        const created = await create();
        const requests = await Promise.all([
          invoke("consume", { provider: "github", state: created.result.outcome.Ok.state }),
          invoke("consume", { provider: "github", state: created.result.outcome.Ok.state }),
        ]);
        const outcomes = requests.map(({ result }) => result.outcome);
        check(outcomes.filter((outcome) => outcome.Ok).length === 1, "one consume wins");
        check(
          outcomes.filter((outcome) => outcome.Err === "already_consumed").length === 1,
          "losing consume is a terminal domain result",
        );
      });

      await run("revoke", async () => {
        const created = await create();
        const state = created.result.outcome.Ok.state;
        const revoked = await invoke("revoke", { provider: "github", state });
        check(revoked.result.outcome.Ok, "revoke must succeed");
        // This invokes a fresh generated App over the same Host-owned store.
        const restarted = await invoke("consume", { provider: "github", state });
        check(
          restarted.result.outcome.Err === "revoked",
          "fresh App must observe persisted revocation",
        );
      });

      await run("expiry", async () => {
        const created = await create();
        created.transport.expireAll();
        const expired = await invoke("consume", {
          provider: "github",
          state: created.result.outcome.Ok.state,
        });
        check(expired.result.outcome.Err === "expired", "expired state must not consume");
      });

      await run("uncertain-commit-reconciles", async () => {
        const created = await create();
        const state = created.result.outcome.Ok.state;
        const dropped = await invoke(
          "consume",
          { provider: "github", state },
          { fault: "after-consume-durable-commit" },
        );
        check(
          dropped.result.outcome.RuntimeFailure === "PluginFailure",
          "dropped response after durable commit must be uncertain at the caller",
        );
        const reconciled = await invoke("consume", { provider: "github", state });
        check(
          reconciled.result.outcome.Err === "already_consumed",
          "fresh App must reconcile the durable terminal state",
        );
      });

      await run("factory-secrecy", async () => {
        let rejected = false;
        const transport = createOAuthPostgresTransport(store);
        const scope = createEventScope(() => ({
          oauth: "0123456789abcdef0123456789abcdef",
          oauthPostgres: transport.execute,
        }));
        try {
          await runner.run(
            () =>
              oauth_postgres_invoke(
                JSON.stringify({
                  operation: "create",
                  request: {
                    provider: "github",
                    return_to: "/settings/security",
                    expires_at: future(),
                  },
                  factory_conflict: true,
                }),
                scope,
              ),
            { scope },
          );
        } catch {
          rejected = true;
        }
        check(rejected, "factory must reject D1/direct-secret conflict");
        check(transport.calls.length === 0, "rejected factory must not call transport");
      });
    } catch (error) {
      cases.push({ name: "unexpected", passed: false, error: String(error) });
    }
    const evidence = {
      schema: "lenso-auth-workers-postgres-cohort-v1",
      environment: "local-workerd",
      passed: cases.length === 6 && cases.every((entry) => entry.passed),
      cases,
      assertion:
        "actual workerd plus generated Auth Wasm and event-owned Host callback; no D1, PostgreSQL, Hyperdrive, deployment, or production claim",
    };
    console.log("AUTH_POSTGRES_COHORT_EVIDENCE " + JSON.stringify(evidence));
    if (!evidence.passed) throw new Error("OAuth PostgreSQL cohort failed");
  },
};
