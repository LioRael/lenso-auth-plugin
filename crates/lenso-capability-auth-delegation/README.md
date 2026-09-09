# Auth Delegation

Private, source-first `lenso.auth.delegation@1` contract. The Account Auth Plugin
provides `grant` to explicitly allowlisted ingress instances.

The caller supplies the selected root session credential, an exact operation
scope and an expiration. Auth derives the user identity and claims from that
session; the caller cannot choose them. Grants cannot exceed one hour or the
parent expiration, widen its audiences, or create nested delegations. A grant
is independently revocable through Credential Issuer. Parent revocation and
account disablement invalidate subsequent authentication of the grant.

The contract does not implement browser consent, CSRF enforcement, credential
custody or Agent login. Those remain ingress and connection responsibilities.
Never expose this operation as a model Tool. Credential Debug fields are
redacted; transport and storage must still treat serialized credentials as
secrets.

Author `src/contract.rs`; regenerate the descriptor, schemas and Rust bindings
with the repository source-first workflow. Do not edit generated artifacts.
