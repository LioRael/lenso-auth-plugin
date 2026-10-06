# Pending operator activation recovery

This source successor adds `lenso.auth.operator-session@1` version 1.1
`resume_binding({binding_id, revision})` and `lenso.auth.operator-binding@1`
version 1.1 `prepare_activation`. The original Binding wire shape and existing
operations remain available. This is a protocol-neutral owner workflow; ingress
keeps credential extraction, accounts realm selection, Origin and CSRF admission.

`resume_binding` requires the configured bootstrap caller and subject, a verified
accounts root-user assertion with the explicit resume audience, live durable
credential/session and source/operator identities, the original finite bootstrap
window, and the exact stored binding ID, canonical revision, issuer, deployment
and scope. Revoked bindings cannot resume. The recovery path never invokes
`prepare_bootstrap`, creates an identity/binding or invokes Access `bootstrap_scope`.
Missing existing Access role/binding management authority rejects recovery.

Each Access create/set/assign call receives a newly issued operators assertion
with only its own operation audience. Its validity ends at the earliest of five
seconds, the source assertion expiry and the configured window end. Internal
contexts retain the absolute parent deadline, request ID and cancellation.
Accounts assertions remain sealed in their original context; source expiry or
revocation requires a new authenticated request rather than a TTL extension.
Session issuance and its permissions/TTL are unchanged and are not part of resume.

Account migration PG8/D1v5 adds two empty-default columns to the existing binding:
`activation_started_at` and `activation_permissions`. The first valid activation
attempt conditionally persists its canonical permissions and timestamp for the
exact pending ID/revision/scope. Retries cannot replace the intent, including
when their proposed timestamp or permissions differ. A different permission
plan rejects instead of mutating an earlier intent. Existing source/operator
subjects, binding IDs, revisions and status are unchanged by migration.

The applied Audit event uses that stable timestamp and permission payload, plus
a stable owner key derived from the binding's issuer/deployment/scope/ID/revision.
It can therefore be replayed through the existing Audit83 idempotency contract
without changing the full payload. Access retains its deterministic role ID,
finite configured permissions plus login, idempotent mutations, protected role
and last-admin checks. Live business/login permissions are checked before Audit
and activation. Only successful Audit precedes the original pending→active CAS.
Response loss or concurrency can complete only by reading the same durable active
binding and complete receipts; active recovery mints no new control assertion.

Apply PG8/D1v5 only with an explicit operator upgrade after source qualification
and deployment approval. Ready does not migrate. Non-operator Account instances
continue read-only admission of their previous PG5/6/7 and D1v2/3/4 histories;
operator-enabled instances require the new history. Reusing the unchanged
`upgrade_operator_bound` owner entrypoint applies the new plan. Already active
legacy rows without activation intent retain their normal session/read behavior;
the new resume operation rejects those rows rather than inventing audit evidence.
For old pending rows with a previously committed legacy random Audit event, the
new stable recovery event is distinct and retains the legacy history; migration
does not infer or backfill an unknown receipt. The reported production pending
case has no applied Audit or business role.

If the original window is closed, an operator must explicitly authorize a new
short window and fresh accounts authentication. Code never reopens it. The new
resume audience must be explicitly included in authorized source credentials.
No production migration, permission repair, credential issuance or retry is
authorized by this source change.

Normal Git consumers must select Account, OperatorSession and the two affected
OperatorBinding/OperatorSession Roles at one qualified successor SHA. Any Console
or Relay typed client for those Roles needs the same source identity; coordinate
its formal owner dependency successor rather than patching Auth in the App.
All eight shared SDK/old Roles remain Git699. The unchanged ManagedSession Role
is explicitly Gitcbaa in Account, so existing renewal/ManagedSession consumers
may stay at cbaa. Owner-only workspace/fixture patches unify this byte-identical
ManagedSession package locally and do not propagate to external Git consumers.
Password, renewal, Core, Access94, Audit83 and the self-contained adapter bytes
remain unchanged. No whole-cohort upgrade or new DB abstraction is needed.

Focused validation is authoring snapshot/Rust projection regeneration for the
two Roles, Account/Operator locked checks and strict clippy, pure context/control
tests, isolated PG intent and original Native App recovery, then actual owner
Workers App/D1 recovery. The non-Cargo `python3 workers/check-activation-intent.py`
uses only in-memory SQLite and real migration/CAS SQL; it is not compiled Rust,
PostgreSQL/D1 transport or App proof. Candidate CI and final consumer App proof
remain required before deployment.
