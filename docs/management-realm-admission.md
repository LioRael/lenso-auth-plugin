# Management realm admission

A realm selects an authentication trust boundary. `RealmAssertionVerifier` in
`lenso-auth-sdk` binds a local realm name to an exact issuer/public key and a
maximum assertion lifetime. Consumers call `project_context` for the precise
Capability operation on every new invocation, after the owning Auth provider
has checked current credential/session state. Same-subject assertions from an
application issuer fail management admission. Claims cannot select a realm.
Targets still own membership, permission checks, credential ceilings and resource
rules; passing this verifier never grants management authority.

Independent Auth instances can share a Directory intentionally while keeping
issuers, signing keys, session state and ingress cookie selection independent.
The verifier keeps the existing Auth 1 wire format and SDK behavior. It does not
rename cookies, migrate sessions, merge subjects by email, or enable a global
realm router. Legacy application consumers retain their explicitly configured
issuer; they do not acquire an operators issuer automatically.

Step-up/MFA requirements currently return `UnsupportedAssurance`. A signed
string such as `mfa` is not evidence that an implementation performed MFA.
Idle session timeout, per-method realm login policy and a remotely manageable
PAT administration Capability remain separate implementation work. This file
records assertion admission only, not a complete production operators profile.

The legacy TypeScript helper now verifies Ed25519 using public authority,
matching Rust. Its fifth argument is the URL-safe base64 public key, replacing
the obsolete HMAC signing-key interpretation. No private signing key belongs at
a target. Claim object ordering is canonicalized to match Rust's BTreeMap.
The supported standalone JS SDK retains ownership of its own projections.

## Verification

```sh
cargo test --locked -p lenso-auth-sdk
node --test crates/lenso-auth-sdk/typescript/actor.test.ts
LENSO_POSTGRES_TEST_URL=postgresql://.../lenso_auth_test_security \
  cargo test --locked -p lenso-auth-account-plugin -p lenso-auth-api-token-plugin \
  --lib -- --include-ignored
```

These verify issuer/key separation, forged realm claims, operation audience,
expiry, lifetime ceilings, unsupported MFA, native credential revocation and
subject-disable races. The PostgreSQL proof uses an isolated local test cluster.
It does not qualify Workers PostgreSQL/Hyperdrive or deployed D1 resources.
