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
Idle session timeout and per-method realm login policy remain separate work.
The Native PostgreSQL human PAT lifecycle is implemented by the
[Human API Token Plugin](../crates/lenso-auth-human-api-token-plugin/README.md),
with exact Account session inspection, constrained issuance and metadata-only
receipts. Browser and ordinary SourceApp qualification require their own
recorded proofs; assertion admission alone does not qualify an operators profile.

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

## Current management credential checks

Account Auth and API Token Auth both provide `lenso.auth.credential-state@1:inspect`.
Bind each trusted issuer to its own state provider; matching subject text does
not permit choosing or combining providers from a request. Account uses an
opaque stored session reference for both IDs, rather than the Cookie value.
Its configured `management_session_ceiling` bounds issuance and current
authentication/inspection, so narrowing or removing the Host ceiling also
restricts existing sessions.
An explicit `credential_state_callers` allowlist admits exact Runtime caller
identities; it defaults to empty. The operation accepts public credential and
session references, never a raw bearer. On every authentication the owner adds
`lenso.auth.credential` to the signed claims. Issuance rejects attempts to supply
that reserved claim. Inspect binds both references to the same owned record,
returns the original subject/kind and current claims/expiry, and reports
`active=false` after token/session revocation or expiry. Missing, substituted
and unauthorized references fail closed. No migration is required.

The SDK `credential` module defines strict `CredentialBinding` and
`ManagementCredentialCeiling` readers. A ceiling contains one exact deployment,
nonempty permissions and nonempty resource scopes; duplicate, unknown and
wildcard fields are rejected. Absence never means unrestricted access. Audience
still controls assertion acceptance, rather than permission or resource scope.
The Management authority must verify the assertion first, requery this owner on
every operation, compare exact signed/current references and subject, and
intersect signed ceiling, current ceiling, deployment eligibility and current
RBAC permission. The target continues its resource-local checks.

Trusted operator issuance may supply a validated management ceiling. Human
creation/delegation adapters must first compute that ceiling from the caller's
current authority; operator access is not exposed to models. The owner operator
`attenuate_management_credential` can only narrow an existing ceiling. PostgreSQL
locks token/session rows and commits claims in one transaction. D1 uses an
exact previous-claims CAS plus current revocation/expiry predicates; a racing
narrow/revoke fails without broadening authority. Revocation is visible to new
inspections; already begun target operations retain their documented validation
window. This adds no cross-database atomicity guarantee.

The Native PostgreSQL generated-port test proves live inspection, exact caller
and reference rejection, secret-free projections, irreversible ceiling
attenuation and visibility of revocation while an old signed assertion remains
unexpired. Worker compilation checks the same private operation adapter; real
D1 vectors require the separately recorded local/remote backend receipt. MFA,
browser idle timeout and browser assembly remain their own qualification items
and cannot be inferred from this primitive. Human PAT mutations are Native
PostgreSQL only; Workers returns `UnsupportedProfile`.

`ApiTokenAuthOperator::list_management_credentials(subject, deployment, limit,
after_credential_id)` exposes secret-free, exact deployment/subject metadata
with bounded keyset pagination for a controlled human CLI. Tokens without an
explicit management ceiling do not enter this projection. It does not reveal
claims, digest, verifier or secret, and its existence does not grant a model or
remote caller operator access. Creation stays a trusted human/operator action;
secret handling is absent from model tool catalogs.

The local backend command is
`node experiments/workers-g4/qualify-credential-state-d1-workerd.mjs /tmp/receipt.json`.
It uses Miniflare's actual workerd/D1 bindings, event-owned transports and the
normal generated Rust Plugin/Capability path, with isolated temporary storage.
The receipt separately identifies local D1 qualification; it is not remote D1
or Hyperdrive deployment evidence. Hyperdrive qualification was deferred by the
owner for this delivery.

## Display profile and optional cache

`AccountAdmin@1` Descriptor 1.1 adds `read_profile`, guarded by the Account
owner's exact `admin_callers`. PostgreSQL migration 5 stores only display name,
avatar URL and a CAS revision. `AccountAuthOperator::update_display_profile`
updates those fields; the read always uses current owner storage. Workers returns
`UnsupportedProfile` for this new display operation and has no display migration.

The removable `lenso.auth.profile` Plugin provides the display-only
`lenso.auth.profile@1` role. Its required named `account` port is an
`AccountAdminClient`; its optional named `profile_cache` port is an
`Option<ProfileCacheClient>`. The separately selected `lenso.auth.profile-cache.memory`
implementation holds bounded, generation-local values with a monotonic TTL.
A cache failure, malformed display value or expiry falls back to the Account read.
Cache values may be stale and cannot include status, sessions, credentials,
assertions, permissions or any other authorization fact. Account `authenticate`,
`CredentialState.inspect`, credential issuance and subject-status reads never
call either display role.

Choose `None` through the normal Source App dependency selection API for
consumer `lenso.auth.profile/default`, requirement `profile_cache`. The persisted
`plugins/.dependencies.json` choice has `provider: null` and remains absent after
restarts, provider removal and provider return. Selecting a cache is an explicit
Host-granted choice; the projection does not create a fallback provider. The
PostgreSQL fixture proves a cached old name remains displayable while a revoked
session is rejected, and restarting with no cache reads the new owner revision.

`lenso_auth_sdk::delegation::denies_human_context` is a denial-only filter for
existing trusted human-decider callers. A forwarded sealed assertion with a
reserved scoped-delegation claim, a non-user actor kind or malformed encoding is
rejected. Missing assertions preserve the explicitly configured trusted-local
caller policy. This helper neither verifies a proof nor grants human authority;
remote boundaries still perform current realm, credential, ceiling and RBAC checks.

## PAT activity metadata

API-token-admin and Human-api-token Descriptor 1.1 add optional `created_at`,
`last_used_at` and `revoked_at` timestamps to credential metadata. Existing wire
requests and operation identifiers remain unchanged. Consumers must use the paired
new generated projection; absence or null means that fact was not recorded.
PostgreSQL migration 3 and D1 migration 2 add only the nullable token activity
column; earlier migration bytes remain unchanged. Existing D1 databases require
an explicit owner `upgrade`, and runtime readiness only verifies the history.

`created_at` comes from the token owner's original insert. `last_used_at` records
an accepted API-token Auth decision while the token and session remain live;
updates are monotonic. Invalid, expired or revoked credentials do not update it.
This timestamp describes authentication, never management or business-write
completion. If activity persistence fails or its commit outcome is uncertain,
Auth returns a runtime failure; callers must report unavailability and may query
current owner state. The persisted time can reflect an accepted owner decision
whose HTTP response was lost. It grants no permission and cannot replace live
CredentialState, ceiling or access checks.

`revoked_at` specifically records explicit token revocation. A revoked session
also makes `active` false, but does not fabricate a token-revocation timestamp.
Receipt and list expose the current owner metadata without a secret. The Native
human/PAT profile remains PostgreSQL-only; D1 evidence covers API token Auth and
operator metadata, not human-facade support on Workers.
