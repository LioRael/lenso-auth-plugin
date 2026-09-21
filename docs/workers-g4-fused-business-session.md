# G4 local fused business session cohort

This qualification is the local `stream/session` **session branch** for the
Task 8 business-composition requirement. It is intentionally a bounded,
source-pinned Miniflare/workerd proof rather than a deployment claim.

## One resolved HTTP plan

The generated G4 `handle_http` entry constructs one Kernel App for every HTTP
event from the same resolved plan. The plan includes:

- Account and OAuth Flow with request-owned D1 factory bindings;
- Auth Router, Web Session, and OIDC Client;
- the generated `proof.business` Plugin, whose typed Auth Port is bound to the
  Router and whose `/auth/proof/business/session` route is selected by Web
  Ingress;
- Web Ingress and HTTP Egress.

The local proof worker sends the controlled IdP token/JWKS exchange through a
second Miniflare/workerd service binding. Browser-style `/fixture/authorize`
navigation is dispatched by the harness directly to that same separate worker,
not through the main wrapper. The cohort does not call an Auth, business, or
Ingress handler directly. The service-bound IdP is synthetic and does not
represent an external provider qualification.

## Receipt contract

Run the cohort from `experiments/workers-g4` with an exact source-closure
Cargo configuration and write the receipt outside the worktree:

```sh
LENSO_CARGO_CONFIG=/private/source-closure.toml CARGO_NET_OFFLINE=true \
  node qualify-fused-session-workerd.mjs --output /private/fused-session.local.json
```

The receipt schema is `lenso.auth.fused-business-session-local-workerd@1` and
contains the exercised source snapshot, Wasm digest, component topology, and
six credential-free cases:

1. Owner migrations use event-owned Account and OAuth D1 bindings.
2. Real ingress rejects an unauthenticated business read.
3. OIDC ingress creates an Account session and lets the business Plugin read it.
4. The session remains valid after a fresh local workerd and Kernel App use the
   same persisted D1 storage.
5. A replayed callback fails without breaking the valid session.
6. CSRF rejection preserves the session, while authorized logout revokes it and
   clears both cookies.

No token, cookie value, state, PKCE verifier, signing key, or synthetic IdP
private key is written to the receipt.

## Boundary

Passing this cohort proves local generated Auth + business Plugin + HTTP + D1
persistence + web-session composition. It does **not** prove a long-lived HTTP
stream or WebSocket lifecycle, remote D1 semantics, deployed Worker behavior,
external IdP interoperability, retention policy, or production operations.
