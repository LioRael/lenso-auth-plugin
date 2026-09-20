# ADR 0008: OAuth Flow environment × infrastructure reference composition

- Status: implemented locally; target qualification remains environment-specific
- Date: 2026-09-20
- Supersedes: the OAuth-specific storage selection portion of ADR 0007

## Decision

`lenso.auth.oauth-flow@1` version 1.2 adds the explicit `revoke` request
operation. OAuth Flow now exposes one portable Contract with `create`,
`consume`, and `revoke`; it does not expose a database, a Hyperdrive binding,
or a Cloudflare resource Capability.

The owned record has exactly one terminal transition:

```text
available --consume--> consumed
available --revoke---> revoked
```

`consume` after revocation returns `revoked`. A second `revoke` returns
`already_revoked`; revoking a consumed flow returns `already_consumed`. A row is
retained instead of deleted so a concurrent caller and a restarted App receive
a truthful terminal result.

The same business Contract is composed through these independent dimensions:

| Execution environment | Private OAuth persistence | Transport owner |
| --- | --- | --- |
| Native | PostgreSQL | Auth's native SQLx/Postgres Kit implementation |
| Workers | D1 | event-owned D1 binding injected by `workers_factory` |
| Workers | PostgreSQL | event-owned Host callback injected by `workers_postgres_factory` |
| Simulator | deterministic store | explicit `OAuthSimulation` test world |

The Host selects the environment and injects its private resource before
activation. `d1_binding` remains a D1-only selection input; an empty direct
database secret is accepted only by the private Workers PostgreSQL factory.
Neither condition creates a Platform API in Auth or Kernel.

## Workers PostgreSQL boundary

`workers_postgres_factory(js_sys::Function)` receives one callback for one
Workers event. It accepts canonical, encrypted-only JSON operations:

```json
{"operation":"create","flow":{...}}
{"operation":"consume","state_digest":"...","provider":"..."}
{"operation":"revoke","state_digest":"...","provider":"..."}
```

The Host returns `created`, `consumed`, `revoked`, or a defined domain outcome.
The callback must implement each `consume` and `revoke` transition as one
PostgreSQL transaction. It must not retry after an uncertain durable mutation.
It may use Cloudflare Hyperdrive, but Hyperdrive configuration, binding names,
connection material, Wrangler, and retry policy remain in the Workers Host.
Auth only sees PostgreSQL persistence semantics and cannot select a transport.

## Simulator boundary

`OAuthSimulation` requires a test-owned wall clock, entropy stream, encryption
key, and optional bounded fault hook. It owns a deterministic private durable
store that is shared by fresh simulated Plugin generations, not by Plugin
instance memory. This lets a test restart an App against the same simulated
durable authority while keeping each Plugin generation fresh.

The simulator is able to prove ordering and business state transitions. It does
not prove SQLx, D1, Hyperdrive, workerd lifecycle, fetch normalization, or
Cloudflare cancellation behavior.

## Storage evolution

OAuth records now retain `revoked_at`:

- PostgreSQL migration 3: `add-oauth-revocation`.
- D1 migration 2: `add-oauth-revocation`.

Existing D1 targets require the owner-controlled migration upgrade workflow;
runtime readiness only verifies history and never mutates it.

## Evidence and qualification

The feature-gated `simulated_reference` integration test crosses the real
native Kernel, resolved Plan, generated Factory, Capability endpoint, and Auth
business implementation. It proves deterministic consume-once, expiration,
revocation, concurrent consume, restart against persistent simulated storage,
and an injected post-commit response loss without retrying the mutation.

Native PostgreSQL, Workers+D1, and Workers+Hyperdrive+PostgreSQL still require
their own target gates with actual provisioned resources. A successful simulator
test or wasm compile is not evidence for those targets. Publication and target
deployment are separate from this implementation decision.
