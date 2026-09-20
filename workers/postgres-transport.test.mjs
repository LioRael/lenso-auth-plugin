import assert from "node:assert/strict";
import test from "node:test";

import {
  createOAuthPostgresStore,
  createOAuthPostgresTransport,
} from "./postgres-transport.mjs";

function flow(stateDigest = "state") {
  return {
    state_digest: stateDigest,
    provider: "github",
    verifier_nonce: "nonce",
    encrypted_verifier: "ciphertext",
    return_to: "/settings/security",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    oidc_nonce: "oidc",
  };
}

async function call(transport, request) {
  return JSON.parse(await transport.execute(JSON.stringify(request)));
}

test("fixture preserves atomic terminal state and transport secrecy", async () => {
  const transport = createOAuthPostgresTransport(createOAuthPostgresStore());
  assert.deepEqual(await call(transport, { operation: "create", flow: flow() }), {
    outcome: "created",
  });
  const consumed = await Promise.all([
    call(transport, {
      operation: "consume",
      state_digest: "state",
      provider: "github",
    }),
    call(transport, {
      operation: "consume",
      state_digest: "state",
      provider: "github",
    }),
  ]);
  assert.equal(consumed.filter((result) => result.outcome === "consumed").length, 1);
  assert.equal(
    consumed.filter((result) => result.error === "already_consumed").length,
    1,
  );
  assert.deepEqual(transport.calls, [
    { operation: "create", keys: ["flow", "operation"] },
    { operation: "consume", keys: ["operation", "provider", "state_digest"] },
    { operation: "consume", keys: ["operation", "provider", "state_digest"] },
  ]);
});

test("fixture makes a post-commit dropped callback result reconcile honestly", async () => {
  const store = createOAuthPostgresStore();
  const normal = createOAuthPostgresTransport(store);
  await call(normal, { operation: "create", flow: flow() });
  const dropped = createOAuthPostgresTransport(store, {
    fault: "after-consume-durable-commit",
  });
  await assert.rejects(
    dropped.execute(
      JSON.stringify({
        operation: "consume",
        state_digest: "state",
        provider: "github",
      }),
    ),
  );
  assert.deepEqual(
    await call(normal, {
      operation: "consume",
      state_digest: "state",
      provider: "github",
    }),
    { outcome: "domain", error: "already_consumed" },
  );
});
