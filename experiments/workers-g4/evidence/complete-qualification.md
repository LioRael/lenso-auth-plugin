# Complete Auth method qualification

Target: `https://lenso-workers-auth-complete-proof.lenso.workers.dev`

Deployment: `ff78dedc-5803-4679-b6d0-3c9ded68f95a` (2026-09-15).
This is a separate test Worker with seven owner-specific D1 databases. It is not
production Marketplace, and no registry package was published by this change.

| Receipt | Passing checks |
| --- | ---: |
| methods.json | 36 |
| method-failures.json | 22 |
| storage-runtime-api.json | 30 |
| session-runtime-api.json | 13 |
| failure-runtime-api.json | 11 |
| egress-runtime-api.json | 5 |
| Total | 117 |

The added methods are Password, Phone, Device, API Token and OIDC Provider.
Coverage includes concurrency, lockout, replay, expiry, missing bindings, storage
failure/recovery, persistent revocation and caller authorization. Node crypto
independently verifies signed assertions and OIDC RS256 ID tokens. SMS and
upstream IdP are controlled fixtures, not external provider qualification.

The existing native PostgreSQL suites passed 33 tests. All seven D1 owner crates
were packaged, extracted outside the checkout and compiled for Wasm with all
non-registry dependencies also supplied as extracted archives. Shared D1 binding
lifecycle/copy-containment tests passed (4 tests).

Native D1 requests cannot be rolled back by local cancellation. An ambiguous
issuance is never automatically retried. Package versions here describe the local
review cohort; registry release and production rollout are separate steps.
