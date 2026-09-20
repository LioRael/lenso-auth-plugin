// Test-only Host implementation of the private OAuth PostgreSQL transport
// protocol. It deliberately lives outside the Auth Plugin: a Workers Host can
// replace it with Hyperdrive-backed PostgreSQL without exposing a binding name,
// connection string, or database handle to Auth.
//
// This file is a local-workerd cohort fixture, not a PostgreSQL or Hyperdrive
// implementation and never produces target/platform qualification by itself.

export function createOAuthPostgresStore() {
  return new Map();
}

export function createOAuthPostgresTransport(store, { fault = null } = {}) {
  const calls = [];

  function domain(error) {
    return JSON.stringify({ outcome: "domain", error });
  }

  function execute(serialized) {
    const request = JSON.parse(serialized);
    calls.push({ operation: request.operation, keys: Object.keys(request).sort() });
    switch (request.operation) {
      case "create": {
        const { flow } = request;
        if (!flow || typeof flow.state_digest !== "string") {
          return Promise.resolve(domain("invalid_state"));
        }
        if (store.has(flow.state_digest)) {
          return Promise.resolve(domain("invalid_state"));
        }
        store.set(flow.state_digest, { flow, terminal: null });
        return Promise.resolve(JSON.stringify({ outcome: "created" }));
      }
      case "consume": {
        const row = store.get(request.state_digest);
        if (!row) return Promise.resolve(domain("invalid_state"));
        if (row.flow.provider !== request.provider) {
          return Promise.resolve(domain("provider_mismatch"));
        }
        if (row.terminal === "consumed") {
          return Promise.resolve(domain("already_consumed"));
        }
        if (row.terminal === "revoked") return Promise.resolve(domain("revoked"));
        if (Date.parse(row.flow.expires_at) <= Date.now()) {
          return Promise.resolve(domain("expired"));
        }
        // This assignment is the fixture's one synchronous durable transition.
        // The fault branch makes the caller observe an uncertain result only
        // after that transition, so the next event must reconcile the truth.
        row.terminal = "consumed";
        if (fault === "after-consume-durable-commit") {
          return Promise.reject(new Error("local callback response dropped"));
        }
        return Promise.resolve(JSON.stringify({ outcome: "consumed", flow: row.flow }));
      }
      case "revoke": {
        const row = store.get(request.state_digest);
        if (!row) return Promise.resolve(domain("invalid_state"));
        if (row.flow.provider !== request.provider) {
          return Promise.resolve(domain("provider_mismatch"));
        }
        if (row.terminal === "consumed") {
          return Promise.resolve(domain("already_consumed"));
        }
        if (row.terminal === "revoked") {
          return Promise.resolve(domain("already_revoked"));
        }
        if (Date.parse(row.flow.expires_at) <= Date.now()) {
          return Promise.resolve(domain("expired"));
        }
        row.terminal = "revoked";
        return Promise.resolve(JSON.stringify({ outcome: "revoked" }));
      }
      default:
        return Promise.reject(new Error("unsupported OAuth transport operation"));
    }
  }

  return {
    calls,
    execute,
    expireAll() {
      for (const row of store.values()) {
        row.flow.expires_at = new Date(Date.now() - 1_000).toISOString();
      }
    },
  };
}
