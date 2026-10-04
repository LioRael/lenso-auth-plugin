# ManagedSession 1.0.0

`lenso.auth.managed-session@1` is a new portable request role. It does not change
CredentialIssuer 1.1 or make legacy sessions renewable.

`issue_managed` receives the authenticated subject and authority from an admitted
authenticator. The provider fixes Instance policy; there is no caller TTL or
profile selector. `renew` receives only sensitive selected credential material.
Both return a sensitive new credential, stable session ID, effective idle expiry,
immutable absolute upper bound, and earliest renewal time as RFC3339 strings.
`read_managed` verifies the current credential and returns the same deadlines
without credential material, rotation or storage mutation. It lets consumers
initialize scheduling or validate the current browser Cookie once after a
concurrent renewal, without modifying the legacy Password login response.

Renewal atomically verifies current credential generation, active subject,
revocation, idle/absolute deadlines and renewal interval, then rotates once.
Authority never increases. An old credential yields `StaleCredential` rather than
another credential; a concurrent loser must not revoke the winner. Unsupported
legacy or delegated credentials are never upgraded by renewal. Storage failures
are Runtime Failures and never anonymous success. Existing revoke-by-ID and
revoke-by-credential must invalidate the managed continuation; subject disable
must serialize with renewal. Providers preserve the original absolute deadline.

The annotated `src/contract.rs` is authoritative. `build.rs` checks source snapshot
freshness and generated projection freshness. Bootstrap with
`LENSO_UPDATE_CONTRACT_SNAPSHOT=1 cargo check -p lenso-capability-managed-session`,
then generate and check the Rust projection with the pinned codegen. The first
bootstrap can report the initially absent generated include after writing the
snapshots. No handwritten Descriptor, schema or projection is an authoring source.

Account is the durable provider. Password is an optional issuance consumer;
Session Renewal is an optional HTTP renewal consumer. Kernel does not interpret
session policy, storage or credential material. Each consumer uses explicit
named bindings and provider-side canonical caller admission.
