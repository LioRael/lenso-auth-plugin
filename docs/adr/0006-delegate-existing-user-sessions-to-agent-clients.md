# ADR 0006: Delegate existing user sessions to Agent clients

- Status: implementation in progress
- Date: 2026-09-10

## Decision and ownership

Account Auth owns delegated credentials as children of an existing authenticated user session. A separate protocol-neutral Delegation Capability exposes constrained issuance; it never accepts a subject, claims or assurance chosen by the consumer. Account Auth copies those facts from the verified parent. Ingress owns browser authentication, CSRF, consent and credential extraction. Projects retains final membership, permission and Team visibility checks.

The first consumer is a local Console Agent connected to a Projects App. Model-provider login and Console control tokens are not Projects identity. Agent connection custody keeps the delegated credential outside prompts, Tool arguments, Session events and diagnostics. A connection change must not silently change the actor of an admitted Turn.

## Grant constraints

A grant has one root user session, a nonempty subset of its exact Capability-operation audiences, a bounded expiration no later than its parent, and a fresh opaque credential. Nested delegation is rejected in this first version. Only explicitly configured ingress callers may request a grant, using the authenticated parent credential. No configured or model-provided user ID is accepted as evidence.

Only token digests are stored. Authentication rechecks parent expiry, revocation and effective subject status on every operation. Revoking the parent or disabling the account invalidates future delegated authentications; already issued signed assertions retain the existing short bounded lifetime. Delegation never restores an expired or revoked credential. It is independently revocable through the existing credential revocation boundary.

A numbered Account-owned migration records the parent relationship. Preparation only verifies the schema; operator setup/upgrade applies migrations explicitly.

## Agent and Projects integration

Use existing Tool declarations and generated clients. Preserve invocation context through Console App Tools and its Host bridge. Cross-process ingress reconstructs only authenticated identity evidence and its own Generation context; it never trusts a serialized caller identity or arbitrary client context. Profile/approval settings cannot widen the delegated grant.

The initial operation proof is Projects issue lookup and revision-checked update. Updates preserve unrelated aggregate fields, use stable idempotency keys, and never automatically retry an ambiguous mutation. Projects audit rows retain the authenticated user subject.

## Acceptance and delivery gates

Prove real parent login, narrowed grant issuance, authorized issue read/update, membership and private-Team denial, missing/expired/revoked grants, parent revocation, restart persistence, revision conflict, cancellation and downstream failure. Assert no denied call changes durable state. Verify credentials do not enter model input, history, logs or Tool outputs.

A live Console/model acceptance and a clean-room npm install follow source and runtime tests. Each report must distinguish source merge, automated tests, live model acceptance and published artifacts. This ADR is not proof those gates have passed.
